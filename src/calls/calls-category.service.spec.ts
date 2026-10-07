import {
  BadRequestException,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import type { PrismaService } from '../prisma/prisma.service';
import { CallsService } from './calls.service';

// These mocks verify transaction composition, not database commit/rollback behavior.
function createService() {
  const category = { id: 'category-1', name: 'Original', color: 'normal' };
  const updated = { ...category, name: 'Renamed' };
  const categoryWrite = Promise.resolve(updated);
  const callsWrite = Promise.resolve({ count: 2 });
  const prisma = {
    callCategory: {
      findUnique: jest.fn().mockResolvedValue(category),
      update: jest.fn().mockReturnValue(categoryWrite),
      create: jest.fn().mockResolvedValue(category),
    },
    call: { updateMany: jest.fn().mockReturnValue(callsWrite) },
    $transaction: jest.fn().mockResolvedValue([updated, { count: 2 }]),
  };
  return {
    service: new CallsService(prisma as unknown as PrismaService),
    prisma,
    category,
    updated,
    categoryWrite,
    callsWrite,
  };
}

function expectNoWrites(prisma: ReturnType<typeof createService>['prisma']) {
  expect(prisma.callCategory.update).not.toHaveBeenCalled();
  expect(prisma.callCategory.create).not.toHaveBeenCalled();
  expect(prisma.call.updateMany).not.toHaveBeenCalled();
  expect(prisma.$transaction).not.toHaveBeenCalled();
}

describe('CallsService category writes', () => {
  describe('updateCategory', () => {
    it('renames the category and only matching calls in the same transaction', async () => {
      const { service, prisma, updated, categoryWrite, callsWrite } =
        createService();

      const result = await service.updateCategory('category-1', {
        name: '  Renamed  ',
      });

      expect(prisma.callCategory.findUnique).toHaveBeenCalledWith({
        where: { id: 'category-1' },
      });
      expect(prisma.callCategory.update).toHaveBeenCalledWith({
        where: { id: 'category-1' },
        data: { name: 'Renamed' },
      });
      expect(prisma.call.updateMany).toHaveBeenCalledWith({
        where: { category: 'Original' },
        data: { category: 'Renamed' },
      });
      expect(prisma.callCategory.update).toHaveBeenCalledTimes(1);
      expect(prisma.call.updateMany).toHaveBeenCalledTimes(1);
      expect(prisma.$transaction).toHaveBeenCalledTimes(1);
      expect(prisma.$transaction).toHaveBeenCalledWith([
        categoryWrite,
        callsWrite,
      ]);
      expect(result).toBe(updated);
    });

    it('keeps color changes in the rename transaction', async () => {
      const { service, prisma } = createService();
      await service.updateCategory('category-1', {
        name: 'Renamed',
        color: 'green',
      });
      expect(prisma.callCategory.update).toHaveBeenCalledWith({
        where: { id: 'category-1' },
        data: { name: 'Renamed', color: 'green' },
      });
      expect(prisma.$transaction).toHaveBeenCalledTimes(1);
      expect(prisma.call.updateMany).toHaveBeenCalledTimes(1);
    });

    it('treats a case-only name change as a rename', async () => {
      const { service, prisma } = createService();
      await service.updateCategory('category-1', { name: 'original' });
      expect(prisma.call.updateMany).toHaveBeenCalledWith({
        where: { category: 'Original' },
        data: { category: 'original' },
      });
      expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    });

    it.each([
      [{ color: 'green' }, { color: 'green' }],
      [{ name: 'Original' }, {}],
      [{ name: '  Original  ', color: 'normal' }, { color: 'normal' }],
      [{}, {}],
    ])(
      'does not rewrite calls for non-rename patch %j',
      async (input, data) => {
        const { service, prisma, updated } = createService();
        await expect(service.updateCategory('category-1', input)).resolves.toBe(
          updated,
        );
        expect(prisma.callCategory.update).toHaveBeenCalledWith({
          where: { id: 'category-1' },
          data,
        });
        expect(prisma.call.updateMany).not.toHaveBeenCalled();
        expect(prisma.$transaction).not.toHaveBeenCalled();
      },
    );

    it('rejects a missing category without writing', async () => {
      const { service, prisma } = createService();
      prisma.callCategory.findUnique.mockResolvedValue(null);
      await expect(
        service.updateCategory('missing', { name: 'Renamed', color: 'green' }),
      ).rejects.toBeInstanceOf(NotFoundException);
      expectNoWrites(prisma);
    });

    it.each(['', '   ', '\t\n'])(
      'rejects empty name %j before writing',
      async (name) => {
        const { service, prisma } = createService();
        await expect(
          service.updateCategory('category-1', { name, color: 'green' }),
        ).rejects.toBeInstanceOf(ConflictException);
        expectNoWrites(prisma);
      },
    );

    it.each(['red', '', 'GREEN'])(
      'rejects invalid color %j before queuing a rename',
      async (color) => {
        const { service, prisma } = createService();
        await expect(
          service.updateCategory('category-1', { name: 'Renamed', color }),
        ).rejects.toBeInstanceOf(BadRequestException);
        expectNoWrites(prisma);
      },
    );

    it('surfaces a failed rename transaction as a conflict', async () => {
      const { service, prisma } = createService();
      prisma.$transaction.mockRejectedValue(new Error('transaction failed'));
      await expect(
        service.updateCategory('category-1', { name: 'Renamed' }),
      ).rejects.toBeInstanceOf(ConflictException);
      expect(prisma.$transaction).toHaveBeenCalledTimes(1);
      expect(prisma.callCategory.update).toHaveBeenCalledTimes(1);
      expect(prisma.call.updateMany).toHaveBeenCalledTimes(1);
    });

    it('surfaces a failed color-only update as a conflict', async () => {
      const { service, prisma } = createService();
      prisma.callCategory.update.mockRejectedValue(new Error('update failed'));
      await expect(
        service.updateCategory('category-1', { color: 'green' }),
      ).rejects.toBeInstanceOf(ConflictException);
      expect(prisma.$transaction).not.toHaveBeenCalled();
      expect(prisma.call.updateMany).not.toHaveBeenCalled();
    });
  });

  describe('createCategory', () => {
    it.each([undefined, 'normal', 'green'])(
      'trims names and accepts color %j',
      async (color) => {
        const { service, prisma, category } = createService();
        await expect(service.createCategory('  New  ', color)).resolves.toBe(
          category,
        );
        expect(prisma.callCategory.create).toHaveBeenCalledWith({
          data: { name: 'New', color: color ?? 'normal' },
        });
      },
    );

    it.each(['', '   '])(
      'rejects empty name %j before writing',
      async (name) => {
        const { service, prisma } = createService();
        await expect(service.createCategory(name)).rejects.toBeInstanceOf(
          ConflictException,
        );
        expectNoWrites(prisma);
      },
    );

    it('rejects an unsupported color before writing', async () => {
      const { service, prisma } = createService();
      await expect(service.createCategory('New', 'red')).rejects.toBeInstanceOf(
        BadRequestException,
      );
      expectNoWrites(prisma);
    });

    it('surfaces a failed create as a conflict', async () => {
      const { service, prisma } = createService();
      prisma.callCategory.create.mockRejectedValue(new Error('duplicate name'));
      await expect(service.createCategory('New')).rejects.toBeInstanceOf(
        ConflictException,
      );
      expect(prisma.callCategory.create).toHaveBeenCalledTimes(1);
    });
  });
});
