import type { Prisma } from '@prisma/client';
import type { PrismaService } from '../prisma/prisma.service';
import { VulnerabilitiesService } from './vulnerabilities.service';

type ExportWorkbook = Prisma.VulnerabilityWorkbookGetPayload<{
  include: { sheets: { include: { rows: true } } };
}>;

const importedAt = new Date('2026-10-01T08:00:00.000Z');
const updatedAt = new Date('2026-10-02T09:00:00.000Z');
const generatedAt = '2026-10-08T10:00:00.000Z';

function workbookFixture(): ExportWorkbook {
  return {
    id: 'db-workbook',
    externalId: 'source-workbook',
    name: 'October review',
    fileName: 'review.xlsx',
    active: true,
    importedAt,
    updatedAt,
    sheets: [
      {
        id: 'db-sheet',
        externalId: 'source-sheet',
        workbookId: 'db-workbook',
        name: 'Findings',
        sheetIndex: 2,
        active: true,
        columns: [
          { id: 'host', label: 'Host', width: 160 },
          { id: 'note', label: '', width: 240 },
          { id: 'missing', label: 'Missing', width: 100 },
        ],
        importedAt,
        updatedAt,
        rows: [
          {
            id: 'db-row',
            externalId: 'source-row',
            sheetId: 'db-sheet',
            rowIndex: 4,
            cells: { host: 'example.test', note: '', extra: 'unmapped value' },
            styles: { host: { bold: true, color: '#123456' } },
            raw: { height: 48 },
            importedAt,
            updatedAt,
          },
        ],
      },
    ],
  };
}

function createService(workbooks: ExportWorkbook[] = [workbookFixture()]) {
  const findMany = jest.fn().mockResolvedValue(workbooks);
  const prisma = { vulnerabilityWorkbook: { findMany } };
  return {
    findMany,
    service: new VulnerabilitiesService(prisma as unknown as PrismaService),
  };
}

describe('VulnerabilitiesService exports', () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(new Date(generatedAt));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('requests ordered workbooks, sheets and rows in one read', async () => {
    const { service, findMany } = createService();

    await service.exportAll();

    expect(findMany).toHaveBeenCalledTimes(1);
    expect(findMany).toHaveBeenCalledWith({
      orderBy: { importedAt: 'desc' },
      include: {
        sheets: {
          orderBy: { sheetIndex: 'asc' },
          include: { rows: { orderBy: { rowIndex: 'asc' } } },
        },
      },
    });
  });

  it('preserves nested identities, source IDs, indices and timestamps', async () => {
    const workbook = workbookFixture();
    const sheet = workbook.sheets[0];
    const row = sheet.rows[0];
    const { service } = createService([workbook]);

    const result = await service.exportAll();

    expect(result.generatedAt).toBe(generatedAt);
    expect(result.workbooks).toEqual([
      {
        id: workbook.id,
        sourceId: workbook.externalId,
        name: workbook.name,
        fileName: workbook.fileName,
        active: true,
        importedAt,
        updatedAt,
        sheets: [
          {
            id: sheet.id,
            sourceId: sheet.externalId,
            name: sheet.name,
            index: 2,
            active: true,
            columns: sheet.columns,
            importedAt,
            updatedAt,
            rows: [
              {
                id: row.id,
                sourceId: row.externalId,
                index: 4,
                cells: row.cells,
                styles: row.styles,
                raw: row.raw,
                importedAt,
                updatedAt,
              },
            ],
          },
        ],
      },
    ]);
  });

  it('links flattened rows to their workbook and sheet without losing raw data', async () => {
    const { service } = createService();

    const result = await service.exportAll();

    expect(result.rows).toEqual([
      {
        workbookId: 'db-workbook',
        workbookSourceId: 'source-workbook',
        workbookName: 'October review',
        sheetId: 'db-sheet',
        sheetSourceId: 'source-sheet',
        sheetName: 'Findings',
        rowId: 'db-row',
        rowSourceId: 'source-row',
        rowIndex: 4,
        values: { Host: 'example.test', note: '', Missing: '' },
        cells: { host: 'example.test', note: '', extra: 'unmapped value' },
        styles: { host: { bold: true, color: '#123456' } },
        raw: { height: 48 },
      },
    ]);
  });

  it('counts empty workbooks and sheets while flattening every nonempty sheet', async () => {
    const first = workbookFixture();
    const second = workbookFixture();
    second.id = 'second-workbook';
    second.externalId = 'second-source';
    second.sheets[0].id = 'second-sheet';
    second.sheets[0].externalId = 'second-sheet-source';
    second.sheets[0].workbookId = second.id;
    second.sheets[0].rows[0].id = 'second-row';
    second.sheets[0].rows[0].externalId = 'second-row-source';
    second.sheets[0].rows[0].sheetId = second.sheets[0].id;
    second.sheets[0].rows.push({
      ...second.sheets[0].rows[0],
      id: 'third-row',
      externalId: 'third-row-source',
      rowIndex: 8,
    });
    first.sheets.push(
      {
        ...first.sheets[0],
        id: 'extra-sheet',
        externalId: 'extra-sheet-source',
        sheetIndex: 3,
        rows: [
          {
            ...first.sheets[0].rows[0],
            id: 'extra-row',
            externalId: 'extra-row-source',
            sheetId: 'extra-sheet',
          },
        ],
      },
      {
        ...first.sheets[0],
        id: 'empty-sheet',
        externalId: 'empty-sheet-source',
        sheetIndex: 4,
        rows: [],
      },
    );
    const empty = {
      ...workbookFixture(),
      id: 'empty-workbook',
      externalId: 'empty-workbook-source',
      sheets: [],
    };
    const { service } = createService([first, second, empty]);

    const result = await service.exportAll();

    expect(result.totalWorkbooks).toBe(3);
    expect(result.totalSheets).toBe(4);
    expect(result.totalRows).toBe(4);
    expect(
      result.rows.map((row) => [row.workbookId, row.sheetId, row.rowId]),
    ).toEqual([
      ['db-workbook', 'db-sheet', 'db-row'],
      ['db-workbook', 'extra-sheet', 'extra-row'],
      ['second-workbook', 'second-sheet', 'second-row'],
      ['second-workbook', 'second-sheet', 'third-row'],
    ]);
    expect(result.workbooks[0].sheets[2].rows).toEqual([]);
    expect(result.workbooks[2].sheets).toEqual([]);
  });

  it('returns a complete empty export when there are no imports', async () => {
    const { service } = createService([]);

    await expect(service.exportAll()).resolves.toEqual({
      generatedAt,
      totalWorkbooks: 0,
      totalSheets: 0,
      totalRows: 0,
      workbooks: [],
      rows: [],
    });
  });

  it('preserves nullable metadata and inactive flags', async () => {
    const workbook = workbookFixture();
    workbook.fileName = null;
    workbook.active = false;
    workbook.sheets[0].active = false;
    workbook.sheets[0].rows[0].externalId = null;
    workbook.sheets[0].rows[0].styles = null;
    const { service } = createService([workbook]);

    const result = await service.exportAll();

    expect(result.workbooks[0]).toMatchObject({
      fileName: null,
      active: false,
    });
    expect(result.workbooks[0].sheets[0]).toMatchObject({ active: false });
    expect(result.workbooks[0].sheets[0].rows[0]).toMatchObject({
      sourceId: null,
      styles: null,
    });
    expect(result.rows[0]).toMatchObject({ rowSourceId: null, styles: null });
  });

  it.each([[], null, {}])(
    'keeps original cells when stored columns are %j',
    async (columns) => {
      const workbook = workbookFixture();
      workbook.sheets[0].columns = columns;
      const { service } = createService([workbook]);

      const result = await service.exportAll();

      expect(result.workbooks[0].sheets[0].columns).toEqual(columns);
      expect(result.rows[0].values).toEqual({});
      expect(result.rows[0].cells).toEqual(workbook.sheets[0].rows[0].cells);
    },
  );

  it('exports the same flattened data without the nested workbook envelope', async () => {
    const { service, findMany } = createService();
    const full = await service.exportAll();
    findMany.mockClear();

    await expect(service.exportRows()).resolves.toEqual({
      generatedAt: full.generatedAt,
      totalRows: full.totalRows,
      rows: full.rows,
    });
    expect(findMany).toHaveBeenCalledTimes(1);
  });

  it.each(['exportAll', 'exportRows'] as const)(
    '%s propagates read failures instead of returning an empty export',
    async (method) => {
      const { service, findMany } = createService();
      const failure = new Error('Read failed');
      findMany.mockRejectedValue(failure);

      await expect(service[method]()).rejects.toBe(failure);
    },
  );
});
