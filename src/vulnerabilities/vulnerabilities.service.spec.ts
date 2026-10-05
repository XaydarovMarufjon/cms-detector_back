import { BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { VulnerabilitiesService } from './vulnerabilities.service';

describe('VulnerabilitiesService snapshot validation', () => {
  function createService() {
    const tx = {
      vulnerabilityWorkbook: {
        deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
        create: jest.fn().mockResolvedValue({ id: 'stored-workbook' }),
      },
      vulnerabilitySheet: {
        create: jest.fn().mockResolvedValue({ id: 'stored-sheet' }),
      },
      vulnerabilityRow: {
        createMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
    };
    const prisma = {
      $transaction: jest.fn(
        async (callback: (client: typeof tx) => Promise<void>) => callback(tx),
      ),
    };

    return {
      prisma,
      tx,
      service: new VulnerabilitiesService(prisma as unknown as PrismaService),
    };
  }

  it.each<{ name: string; payload: unknown }>([
    { name: 'null payload', payload: null },
    { name: 'undefined payload', payload: undefined },
    { name: 'string payload', payload: 'invalid' },
    { name: 'number payload', payload: 42 },
    { name: 'boolean payload', payload: true },
    { name: 'array payload', payload: [] },
    { name: 'missing sheets', payload: {} },
    { name: 'metadata without sheets', payload: { fileName: 'report.xlsx' } },
    { name: 'null sheets', payload: { sheets: null } },
    { name: 'object sheets', payload: { sheets: {} } },
    { name: 'string sheets', payload: { sheets: 'invalid' } },
    { name: 'number sheets', payload: { sheets: 42 } },
    { name: 'boolean sheets', payload: { sheets: false } },
  ])(
    'rejects $name without starting a destructive transaction',
    async ({ payload }) => {
      const { service, prisma, tx } = createService();

      await expect(service.replaceSnapshot(payload)).rejects.toBeInstanceOf(
        BadRequestException,
      );

      expect(prisma.$transaction).not.toHaveBeenCalled();
      expect(tx.vulnerabilityWorkbook.deleteMany).not.toHaveBeenCalled();
      expect(tx.vulnerabilityWorkbook.create).not.toHaveBeenCalled();
    },
  );

  it.each([null, undefined, 'invalid', 42, true, []])(
    'rejects malformed sheet %p before replacing any workbooks',
    async (sheet) => {
      const { service, prisma, tx } = createService();

      await expect(
        service.replaceSnapshot({ sheets: [{ id: 'valid-sheet' }, sheet] }),
      ).rejects.toBeInstanceOf(BadRequestException);

      expect(prisma.$transaction).not.toHaveBeenCalled();
      expect(tx.vulnerabilityWorkbook.deleteMany).not.toHaveBeenCalled();
    },
  );

  describe.each(['columns', 'rows'])('%s validation', (field) => {
    it.each([null, 'invalid', 42, true, {}])(
      'rejects a non-array field %p without deleting imports',
      async (value) => {
        const { service, prisma, tx } = createService();

        await expect(
          service.replaceSnapshot({ sheets: [{ [field]: value }] }),
        ).rejects.toBeInstanceOf(BadRequestException);

        expect(prisma.$transaction).not.toHaveBeenCalled();
        expect(tx.vulnerabilityWorkbook.deleteMany).not.toHaveBeenCalled();
      },
    );

    it.each([null, undefined, 'invalid', 42, true, []])(
      'rejects a malformed element %p without deleting imports',
      async (value) => {
        const { service, prisma, tx } = createService();

        await expect(
          service.replaceSnapshot({ sheets: [{ [field]: [{}, value] }] }),
        ).rejects.toBeInstanceOf(BadRequestException);

        expect(prisma.$transaction).not.toHaveBeenCalled();
        expect(tx.vulnerabilityWorkbook.deleteMany).not.toHaveBeenCalled();
      },
    );
  });

  it.each([null, 'invalid', 42, true, []])(
    'rejects malformed row cells %p without deleting imports',
    async (cells) => {
      const { service, prisma, tx } = createService();

      await expect(
        service.replaceSnapshot({ sheets: [{ rows: [{ cells }] }] }),
      ).rejects.toBeInstanceOf(BadRequestException);

      expect(prisma.$transaction).not.toHaveBeenCalled();
      expect(tx.vulnerabilityWorkbook.deleteMany).not.toHaveBeenCalled();
    },
  );

  it.each(['invalid', 42, true, []])(
    'rejects malformed row styles %p without deleting imports',
    async (styles) => {
      const { service, prisma, tx } = createService();

      await expect(
        service.replaceSnapshot({ sheets: [{ rows: [{ styles }] }] }),
      ).rejects.toBeInstanceOf(BadRequestException);

      expect(prisma.$transaction).not.toHaveBeenCalled();
      expect(tx.vulnerabilityWorkbook.deleteMany).not.toHaveBeenCalled();
    },
  );

  it('preserves an explicitly empty snapshot as a request to clear imports', async () => {
    const { service, prisma, tx } = createService();

    await expect(service.replaceSnapshot({ sheets: [] })).resolves.toEqual({
      workbooks: 0,
      sheets: 0,
      rows: 0,
    });

    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(tx.vulnerabilityWorkbook.deleteMany).toHaveBeenCalledWith({});
    expect(tx.vulnerabilityWorkbook.create).not.toHaveBeenCalled();
    expect(tx.vulnerabilitySheet.create).not.toHaveBeenCalled();
    expect(tx.vulnerabilityRow.createMany).not.toHaveBeenCalled();
  });

  it('continues to normalize and save a valid frontend snapshot', async () => {
    const { service, prisma, tx } = createService();

    const result = await service.replaceSnapshot({
      activeWorkbookId: 'workbook-1',
      activeSheetId: 'sheet-1',
      fileName: 'report.xlsx',
      sheets: [
        {
          id: 'sheet-1',
          name: 'Findings',
          workbookId: 'workbook-1',
          workbookName: 'Report',
          columns: [{ id: 'title', label: 'Title', width: 200 }],
          rows: [
            {
              id: 'row-1',
              height: 35,
              cells: { title: '  Finding  ' },
              styles: { title: { bold: true } },
            },
          ],
        },
        { id: 'sheet-2', workbookId: 'workbook-1', workbookName: 'Report' },
      ],
    });

    expect(result).toEqual({ workbooks: 1, sheets: 2, rows: 1 });
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(tx.vulnerabilityWorkbook.deleteMany).toHaveBeenCalledWith({});
    expect(tx.vulnerabilityWorkbook.create).toHaveBeenCalledTimes(1);
    expect(tx.vulnerabilityWorkbook.create).toHaveBeenCalledWith({
      data: {
        externalId: 'workbook-1',
        name: 'Report',
        fileName: 'report.xlsx',
        active: true,
      },
    });
    expect(tx.vulnerabilitySheet.create).toHaveBeenCalledTimes(2);
    expect(tx.vulnerabilitySheet.create).toHaveBeenNthCalledWith(1, {
      data: {
        externalId: 'sheet-1',
        workbookId: 'stored-workbook',
        name: 'Findings',
        sheetIndex: 0,
        active: true,
        columns: [{ id: 'title', label: 'Title', width: 200 }],
      },
    });
    expect(tx.vulnerabilitySheet.create).toHaveBeenNthCalledWith(2, {
      data: {
        externalId: 'sheet-2',
        workbookId: 'stored-workbook',
        name: 'Sheet 2',
        sheetIndex: 1,
        active: false,
        columns: [],
      },
    });
    expect(tx.vulnerabilityRow.createMany).toHaveBeenCalledTimes(1);
    expect(tx.vulnerabilityRow.createMany).toHaveBeenCalledWith({
      data: [
        {
          externalId: 'row-1',
          sheetId: 'stored-sheet',
          rowIndex: 0,
          cells: { title: 'Finding' },
          styles: { title: { bold: true } },
          raw: { height: 35 },
        },
      ],
    });
  });

  it('keeps explicit empty containers and optional null styles valid', async () => {
    const { service, tx } = createService();

    await expect(
      service.replaceSnapshot({
        sheets: [
          { columns: [], rows: [] },
          { rows: [{ cells: {}, styles: null }, {}] },
        ],
      }),
    ).resolves.toEqual({ workbooks: 1, sheets: 2, rows: 0 });

    expect(tx.vulnerabilitySheet.create).toHaveBeenCalledTimes(2);
    expect(tx.vulnerabilityRow.createMany).not.toHaveBeenCalled();
  });
});
