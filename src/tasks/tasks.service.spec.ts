import { BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { TasksService } from './tasks.service';

describe('TasksService due dates', () => {
  function createService() {
    const prisma = {
      securityTask: {
        create: jest
          .fn<Promise<{ id: string }>, [{ data: { dueDate?: Date | null } }]>()
          .mockResolvedValue({ id: 'task-1' }),
        update: jest
          .fn<Promise<{ id: string }>, [{ data: { dueDate?: Date | null } }]>()
          .mockResolvedValue({ id: 'task-1' }),
      },
    };

    return {
      prisma,
      service: new TasksService(prisma as unknown as PrismaService),
    };
  }

  describe.each(['create', 'update'] as const)('%s', (operation) => {
    function writeTask(service: TasksService, dueDate: unknown) {
      const input = { title: 'Review findings', dueDate };
      // JSON request bodies are not checked by TypeScript at runtime.
      if (operation === 'create') {
        return service.create(input as Parameters<TasksService['create']>[0]);
      }
      return service.update(
        'task-1',
        input as Parameters<TasksService['update']>[1],
      );
    }

    it.each([
      ['unparseable text', 'not-a-date'],
      ['invalid month', '2026-13-04'],
      ['whitespace', '   '],
      ['numeric timestamp', 1_791_072_000_000],
      ['zero', 0],
      ['boolean', false],
      ['object', {}],
      ['array', ['2026-10-04']],
    ])('rejects %s before writing to the database', (_label, dueDate) => {
      const { prisma, service } = createService();

      expect(() => writeTask(service, dueDate)).toThrow(BadRequestException);
      expect(prisma.securityTask.create).not.toHaveBeenCalled();
      expect(prisma.securityTask.update).not.toHaveBeenCalled();
    });

    it.each([
      ['2026-10-04', '2026-10-04T00:00:00.000Z'],
      ['2026-10-04T14:30:00.000Z', '2026-10-04T14:30:00.000Z'],
      ['2026-10-04T14:30:00+05:00', '2026-10-04T09:30:00.000Z'],
    ])('preserves valid date %s', async (dueDate, expected) => {
      const { prisma, service } = createService();

      await writeTask(service, dueDate);

      expect(prisma.securityTask[operation]).toHaveBeenCalledTimes(1);
      expect(
        prisma.securityTask[operation].mock.calls[0][0].data.dueDate,
      ).toEqual(new Date(expected));
    });

    it.each([null, ''])(
      'clears an explicit empty due date (%s)',
      async (dueDate) => {
        const { prisma, service } = createService();

        await writeTask(service, dueDate);

        expect(prisma.securityTask[operation]).toHaveBeenCalledTimes(1);
        expect(
          prisma.securityTask[operation].mock.calls[0][0].data.dueDate,
        ).toBeNull();
      },
    );
  });

  it('creates a task without a due date', async () => {
    const { prisma, service } = createService();

    await service.create({ title: 'Review findings' });

    expect(prisma.securityTask.create).toHaveBeenCalledTimes(1);
    expect(prisma.securityTask.create.mock.calls[0][0].data.dueDate).toBeNull();
  });

  it('leaves the existing due date unchanged when omitted from an update', async () => {
    const { prisma, service } = createService();

    await service.update('task-1', { title: 'Updated title' });

    expect(prisma.securityTask.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: { title: 'Updated title' } }),
    );
  });
});
