import { PrismaService } from '../prisma/prisma.service';
import { VulnerabilitiesService } from './vulnerabilities.service';

// These mocks check transaction composition and sequencing, not database rollback.
describe('VulnerabilitiesService snapshot transaction', () => {
  function createService() {
    let workbookId = 0;
    let sheetId = 0;
    const operations: string[] = [];
    const tx = {
      vulnerabilityWorkbook: {
        deleteMany: jest.fn().mockImplementation(() => {
          operations.push('delete');
          return Promise.resolve({ count: 3 });
        }),
        create: jest.fn().mockImplementation(() => {
          operations.push('workbook');
          return Promise.resolve({ id: `db-workbook-${++workbookId}` });
        }),
      },
      vulnerabilitySheet: {
        create: jest.fn().mockImplementation(() => {
          operations.push('sheet');
          return Promise.resolve({ id: `db-sheet-${++sheetId}` });
        }),
      },
      vulnerabilityRow: {
        createMany: jest.fn().mockImplementation(() => {
          operations.push('rows');
          return Promise.resolve({ count: 1 });
        }),
      },
    };
    const prisma = {
      $transaction: jest.fn(
        async (callback: (client: typeof tx) => Promise<void>) => callback(tx),
      ),
    };
    return {
      tx,
      prisma,
      operations,
      service: new VulnerabilitiesService(prisma as unknown as PrismaService),
    };
  }

  function snapshot() {
    const sheet = (id: string, workbookId: string) => ({
      id,
      name: `Sheet ${id}`,
      workbookId,
      workbookName: `Book ${workbookId}`,
      columns: [{ id: 'finding', label: 'Finding', width: 200 }],
      rows: [{ id: `row-${id}`, cells: { finding: `Value ${id}` } }],
    });
    return {
      activeWorkbookId: 'b',
      activeSheetId: 'a2',
      fileName: ' findings.xlsx ',
      sheets: [sheet('a1', 'a'), sheet('b1', 'b'), sheet('a2', 'a')],
    };
  }

  it('groups interleaved workbooks while using returned database parent IDs', async () => {
    const { service, prisma, tx, operations } = createService();
    await expect(service.replaceSnapshot(snapshot())).resolves.toEqual({
      workbooks: 2,
      sheets: 3,
      rows: 3,
    });
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(tx.vulnerabilityWorkbook.deleteMany).toHaveBeenCalledWith({});
    expect(tx.vulnerabilityWorkbook.deleteMany).toHaveBeenCalledTimes(1);
    expect(tx.vulnerabilityWorkbook.create.mock.calls).toEqual([
      [
        {
          data: {
            externalId: 'a',
            name: 'Book a',
            fileName: 'findings.xlsx',
            active: false,
          },
        },
      ],
      [
        {
          data: {
            externalId: 'b',
            name: 'Book b',
            fileName: 'findings.xlsx',
            active: true,
          },
        },
      ],
    ]);
    expect(tx.vulnerabilitySheet.create.mock.calls).toEqual([
      [
        {
          data: {
            externalId: 'a1',
            workbookId: 'db-workbook-1',
            name: 'Sheet a1',
            sheetIndex: 0,
            active: false,
            columns: [{ id: 'finding', label: 'Finding', width: 200 }],
          },
        },
      ],
      [
        {
          data: {
            externalId: 'a2',
            workbookId: 'db-workbook-1',
            name: 'Sheet a2',
            sheetIndex: 2,
            active: true,
            columns: [{ id: 'finding', label: 'Finding', width: 200 }],
          },
        },
      ],
      [
        {
          data: {
            externalId: 'b1',
            workbookId: 'db-workbook-2',
            name: 'Sheet b1',
            sheetIndex: 1,
            active: false,
            columns: [{ id: 'finding', label: 'Finding', width: 200 }],
          },
        },
      ],
    ]);
    expect(tx.vulnerabilityRow.createMany.mock.calls).toEqual(
      ['a1', 'a2', 'b1'].map((id, index) => [
        {
          data: [
            {
              externalId: `row-${id}`,
              sheetId: `db-sheet-${index + 1}`,
              rowIndex: 0,
              cells: { finding: `Value ${id}` },
              styles: null,
              raw: { height: 35 },
            },
          ],
        },
      ]),
    );
    expect(operations).toEqual([
      'delete',
      'workbook',
      'sheet',
      'rows',
      'sheet',
      'rows',
      'workbook',
      'sheet',
      'rows',
    ]);
  });

  it('retains original row positions after filtering blank rows and counts only persisted rows', async () => {
    const { service, tx } = createService();
    const input = {
      sheets: [
        {
          id: 'sheet',
          columns: [{ id: 'finding' }, { id: 'count' }],
          rows: [
            { cells: { finding: ' \n ' } },
            {
              id: 'second',
              height: 44,
              cells: { finding: ' A\n B ', count: 0, extra: 'ignored' },
              styles: { finding: { bold: true } },
            },
            { cells: {} },
            { id: 'fourth', cells: { finding: false } },
          ],
        },
      ],
    };
    const original = JSON.stringify(input);
    await expect(service.replaceSnapshot(input)).resolves.toEqual({
      workbooks: 1,
      sheets: 1,
      rows: 2,
    });
    expect(tx.vulnerabilityRow.createMany).toHaveBeenCalledTimes(1);
    expect(tx.vulnerabilityRow.createMany).toHaveBeenCalledWith({
      data: [
        {
          externalId: 'second',
          sheetId: 'db-sheet-1',
          rowIndex: 1,
          cells: { finding: 'A B', count: '0' },
          styles: { finding: { bold: true } },
          raw: { height: 44 },
        },
        {
          externalId: 'fourth',
          sheetId: 'db-sheet-1',
          rowIndex: 3,
          cells: { finding: 'false', count: '' },
          styles: null,
          raw: { height: 35 },
        },
      ],
    });
    expect(JSON.stringify(input)).toBe(original);
  });

  it('keeps empty sheets without issuing an empty row insert', async () => {
    const { service, tx } = createService();
    const input = snapshot();
    input.sheets[0].rows = [];
    input.sheets[1].rows = [{ id: 'blank', cells: { finding: ' ' } }];
    await expect(service.replaceSnapshot(input)).resolves.toEqual({
      workbooks: 2,
      sheets: 3,
      rows: 1,
    });
    expect(tx.vulnerabilitySheet.create).toHaveBeenCalledTimes(3);
    expect(tx.vulnerabilityRow.createMany).toHaveBeenCalledTimes(1);
    expect(tx.vulnerabilityRow.createMany).toHaveBeenCalledWith({
      data: [
        expect.objectContaining({
          sheetId: 'db-sheet-2',
          externalId: 'row-a2',
        }),
      ],
    });
  });

  it.each<{
    stage: 'delete' | 'workbook' | 'sheet' | 'rows';
    before: string[];
  }>([
    { stage: 'delete', before: [] },
    { stage: 'workbook', before: ['delete'] },
    { stage: 'sheet', before: ['delete', 'workbook'] },
    { stage: 'rows', before: ['delete', 'workbook', 'sheet'] },
  ])(
    'propagates a $stage failure without continuing the replacement',
    async ({ stage, before }) => {
      const { service, tx, operations } = createService();
      const error = new Error(`${stage} failed`);
      const methods = {
        delete: tx.vulnerabilityWorkbook.deleteMany,
        workbook: tx.vulnerabilityWorkbook.create,
        sheet: tx.vulnerabilitySheet.create,
        rows: tx.vulnerabilityRow.createMany,
      };
      methods[stage].mockRejectedValueOnce(error);
      await expect(service.replaceSnapshot(snapshot())).rejects.toBe(error);
      expect(operations).toEqual(before);
    },
  );

  it('stops after a later row batch fails, before creating the next workbook', async () => {
    const { service, tx, operations } = createService();
    const error = new Error('second batch failed');
    tx.vulnerabilityRow.createMany
      .mockImplementationOnce(() => {
        operations.push('rows');
        return Promise.resolve({ count: 1 });
      })
      .mockRejectedValueOnce(error);
    await expect(service.replaceSnapshot(snapshot())).rejects.toBe(error);
    expect(tx.vulnerabilityWorkbook.create).toHaveBeenCalledTimes(1);
    expect(tx.vulnerabilitySheet.create).toHaveBeenCalledTimes(2);
    expect(tx.vulnerabilityRow.createMany).toHaveBeenCalledTimes(2);
    expect(operations).toEqual([
      'delete',
      'workbook',
      'sheet',
      'rows',
      'sheet',
    ]);
  });

  it('propagates failure to start a transaction without performing writes', async () => {
    const { service, prisma, operations } = createService();
    const error = new Error('transaction unavailable');
    prisma.$transaction.mockRejectedValueOnce(error);
    await expect(service.replaceSnapshot(snapshot())).rejects.toBe(error);
    expect(operations).toEqual([]);
  });

  it('does not report success if transaction completion fails after all writes', async () => {
    const { service, prisma, tx, operations } = createService();
    const error = new Error('commit failed');
    prisma.$transaction.mockImplementationOnce(async (callback) => {
      await callback(tx);
      operations.push('completion rejected');
      throw error;
    });
    await expect(service.replaceSnapshot(snapshot())).rejects.toBe(error);
    expect(tx.vulnerabilityWorkbook.create).toHaveBeenCalledTimes(2);
    expect(tx.vulnerabilitySheet.create).toHaveBeenCalledTimes(3);
    expect(tx.vulnerabilityRow.createMany).toHaveBeenCalledTimes(3);
    expect(operations.at(-1)).toBe('completion rejected');
  });

  it('awaits deletion before creating replacement workbooks', async () => {
    const { service, tx } = createService();
    let finishDelete!: (value: { count: number }) => void;
    tx.vulnerabilityWorkbook.deleteMany.mockReturnValueOnce(
      new Promise<{ count: number }>((resolve) => {
        finishDelete = resolve;
      }),
    );
    const pending = service.replaceSnapshot(snapshot());
    try {
      await Promise.resolve();
      expect(tx.vulnerabilityWorkbook.create).not.toHaveBeenCalled();
    } finally {
      finishDelete({ count: 3 });
      await pending;
    }
    await expect(pending).resolves.toEqual({
      workbooks: 2,
      sheets: 3,
      rows: 3,
    });
  });

  it('does not leak grouped sheets or counts into a subsequent replacement', async () => {
    const { service, tx, prisma } = createService();
    await service.replaceSnapshot(snapshot());
    tx.vulnerabilityWorkbook.create.mockClear();
    tx.vulnerabilitySheet.create.mockClear();
    tx.vulnerabilityRow.createMany.mockClear();
    await expect(service.replaceSnapshot({ sheets: [] })).resolves.toEqual({
      workbooks: 0,
      sheets: 0,
      rows: 0,
    });
    expect(prisma.$transaction).toHaveBeenCalledTimes(2);
    expect(tx.vulnerabilityWorkbook.deleteMany).toHaveBeenCalledTimes(2);
    expect(tx.vulnerabilityWorkbook.create).not.toHaveBeenCalled();
    expect(tx.vulnerabilitySheet.create).not.toHaveBeenCalled();
    expect(tx.vulnerabilityRow.createMany).not.toHaveBeenCalled();
  });
});
