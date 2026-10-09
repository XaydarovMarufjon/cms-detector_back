import type { Prisma } from '@prisma/client';
import type { PrismaService } from '../prisma/prisma.service';
import { VulnerabilitiesService } from './vulnerabilities.service';

type ExportWorkbook = Prisma.VulnerabilityWorkbookGetPayload<{
  include: { sheets: { include: { rows: true } } };
}>;

type Column = { id: string; label: string; width: number };

const column = (id: string, label: string): Column => ({
  id,
  label,
  width: 160,
});

function workbookFixture(
  columns: Column[],
  cells: Record<string, string>,
): ExportWorkbook {
  const timestamp = new Date('2026-10-09T08:00:00.000Z');
  return {
    id: 'workbook',
    externalId: 'source-workbook',
    name: 'Collision example',
    fileName: 'example.xlsx',
    active: true,
    importedAt: timestamp,
    updatedAt: timestamp,
    sheets: [
      {
        id: 'sheet',
        externalId: 'source-sheet',
        workbookId: 'workbook',
        name: 'Findings',
        sheetIndex: 0,
        active: true,
        columns,
        importedAt: timestamp,
        updatedAt: timestamp,
        rows: [
          {
            id: 'row',
            externalId: 'source-row',
            sheetId: 'sheet',
            rowIndex: 0,
            cells,
            styles: null,
            raw: { height: 35 },
            importedAt: timestamp,
            updatedAt: timestamp,
          },
        ],
      },
    ],
  };
}

function createService(workbook: ExportWorkbook) {
  const prisma = {
    vulnerabilityWorkbook: {
      findMany: jest.fn().mockResolvedValue([workbook]),
    },
  };
  return new VulnerabilitiesService(prisma as unknown as PrismaService);
}

// These cases describe current limitations, not a preferred permanent API.
// A deliberate change to `values` should update these cases and the consumer guide.
describe.each(['exportAll', 'exportRows'] as const)(
  'VulnerabilitiesService %s column collisions',
  (method) => {
    it.each<{ name: string; cells: Record<string, string> }>([
      { name: 'populated', cells: { first: 'earlier', last: 'later' } },
      { name: 'empty', cells: { first: 'earlier', last: '' } },
      { name: 'missing', cells: { first: 'earlier' } },
    ])(
      'characterizes a $name final duplicate while retaining ID-keyed cells',
      async ({ cells }) => {
        const workbook = workbookFixture(
          [column('first', 'Status'), column('last', 'Status')],
          cells,
        );
        const service = createService(workbook);

        const result = await service[method]();

        expect(result.rows[0].values).toEqual({ Status: cells.last ?? '' });
        expect(result.rows[0].cells).toEqual(cells);
        expect(workbook.sheets[0].rows[0].cells).toEqual(cells);
      },
    );

    it.each([
      {
        name: 'fallback after label',
        columns: [column('first', 'shared'), column('shared', '')],
        expected: 'fallback value',
      },
      {
        name: 'label after fallback',
        columns: [column('shared', ''), column('first', 'shared')],
        expected: 'label value',
      },
    ])(
      'characterizes $name collisions in stored column order',
      async (test) => {
        const cells = { first: 'label value', shared: 'fallback value' };
        const service = createService(workbookFixture(test.columns, cells));

        const result = await service[method]();

        expect(result.rows[0].values).toEqual({ shared: test.expected });
        expect(result.rows[0].cells).toEqual(cells);
      },
    );

    it('keeps case-distinct labels separate', async () => {
      const service = createService(
        workbookFixture([column('first', 'Status'), column('last', 'status')], {
          first: 'upper',
          last: 'lower',
        }),
      );

      const result = await service[method]();

      expect(result.rows[0].values).toEqual({
        Status: 'upper',
        status: 'lower',
      });
    });

    it('characterizes special object-key labels without losing ID-keyed cells', async () => {
      const columns = [
        column('a', '__proto__'),
        column('b', 'constructor'),
        column('c', 'toString'),
      ];
      const cells = {
        a: 'prototype text',
        b: 'constructor text',
        c: 'string text',
      };
      const workbook = workbookFixture(columns, cells);
      const service = createService(workbook);

      const result = await service[method]();

      // Assignment to __proto__ on the current plain-object map omits this key.
      expect(Object.hasOwn(result.rows[0].values, '__proto__')).toBe(false);
      expect(JSON.stringify(result.rows[0].values)).toBe(
        JSON.stringify({ constructor: cells.b, toString: cells.c }),
      );
      expect(result.rows[0].cells).toEqual(cells);
      expect(workbook.sheets[0].columns).toEqual(columns);
    });
  },
);

describe('VulnerabilitiesService lossless positional exports', () => {
  it('keeps repeated and special labels and every position after JSON serialization', async () => {
    const columns = [
      column('a', 'Status'),
      column('b', 'Status'),
      column('c', '__proto__'),
      column('d', ''),
    ];
    const cells = {
      a: 'open',
      b: 'reviewed',
      c: 'literal header',
      d: 'fallback',
    };
    const workbook = workbookFixture(columns, cells);
    const before = JSON.stringify(workbook);
    const result = await createService(workbook).exportAll();
    const wire = JSON.parse(JSON.stringify(result)) as typeof result;
    const sheet = wire.workbooks[0].sheets[0];

    expect(sheet.columns).toEqual(columns);
    expect(sheet.rows[0].cells).toEqual(cells);
    // Same positional reconstruction as docs/vulnerability-exports.md.
    const exportedColumns = sheet.columns as Column[];
    const exportedCells = sheet.rows[0].cells as Record<string, string>;
    expect(exportedColumns.map((entry) => entry.label || entry.id)).toEqual([
      'Status',
      'Status',
      '__proto__',
      'd',
    ]);
    expect(
      exportedColumns.map((entry) => exportedCells[entry.id] ?? ''),
    ).toEqual(['open', 'reviewed', 'literal header', 'fallback']);
    expect(JSON.stringify(workbook)).toBe(before);
  });

  it('does not share label maps between rows or sheets', async () => {
    const workbook = workbookFixture(
      [column('a', 'Status'), column('b', 'Status')],
      { a: 'first earlier', b: 'first later' },
    );
    const sheet = workbook.sheets[0];
    sheet.rows.push({
      ...sheet.rows[0],
      id: 'second-row',
      rowIndex: 1,
      cells: { a: 'second earlier', b: 'second later' },
    });
    workbook.sheets.push({
      ...sheet,
      id: 'second-sheet',
      sheetIndex: 1,
      columns: [column('only', 'Status')],
      rows: [
        { ...sheet.rows[0], sheetId: 'second-sheet', cells: { only: 'third' } },
      ],
    });

    const result = await createService(workbook).exportAll();

    expect(result.rows.map((row) => row.values)).toEqual([
      { Status: 'first later' },
      { Status: 'second later' },
      { Status: 'third' },
    ]);
    expect(result.rows.map((row) => row.cells)).toEqual([
      { a: 'first earlier', b: 'first later' },
      { a: 'second earlier', b: 'second later' },
      { only: 'third' },
    ]);
    expect(result.rows[0].values).not.toBe(result.rows[1].values);
    expect(result.rows[1].values).not.toBe(result.rows[2].values);
  });
});
