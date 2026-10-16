import { BadRequestException } from '@nestjs/common';
import type { PrismaService } from '../prisma/prisma.service';
import { TasksService } from './tasks.service';

type Patch = Parameters<TasksService['update']>[1];

function createService() {
  const saved = { id: 'task-1', title: 'Stored title' };
  const update = jest.fn().mockResolvedValue(saved);
  const prisma = { securityTask: { update } };
  return {
    service: new TasksService(prisma as unknown as PrismaService),
    update,
    saved,
  };
}

const include = {
  website: { select: { id: true, url: true, label: true } },
  assignee: { select: { id: true, username: true, role: true } },
  createdBy: { select: { id: true, username: true, role: true } },
};

// Verify the Prisma write contract only; no database or HTTP server is started.
// Date parsing has separate coverage in the proposed due-date validation change.
describe('TasksService partial-update fields', () => {
  it.each<Patch>([
    {},
    {
      title: undefined,
      description: undefined,
      source: undefined,
      priority: undefined,
      status: undefined,
      websiteId: undefined,
      assigneeId: undefined,
    },
  ])('does not reset omitted fields for patch %j', async (patch) => {
    const { service, update, saved } = createService();

    await expect(service.update('task-1', patch)).resolves.toBe(saved);

    expect(update).toHaveBeenCalledTimes(1);
    expect(update).toHaveBeenCalledWith({
      where: { id: 'task-1' },
      data: {},
      include,
    });
  });

  it.each<{ patch: Patch; data: Record<string, unknown> }>([
    {
      patch: { title: '  Review findings  ' },
      data: { title: 'Review findings' },
    },
    {
      patch: { description: '  Next step  ' },
      data: { description: 'Next step' },
    },
    { patch: { description: '' }, data: { description: null } },
    { patch: { description: ' \t\n ' }, data: { description: null } },
    { patch: { websiteId: 'site-2' }, data: { websiteId: 'site-2' } },
    { patch: { websiteId: null }, data: { websiteId: null } },
    { patch: { websiteId: '' }, data: { websiteId: null } },
    { patch: { assigneeId: 'user-2' }, data: { assigneeId: 'user-2' } },
    { patch: { assigneeId: null }, data: { assigneeId: null } },
    { patch: { assigneeId: '' }, data: { assigneeId: null } },
  ])('updates only the supplied field: $patch', async ({ patch, data }) => {
    const { service, update } = createService();

    await service.update('task-1', patch);

    expect(update).toHaveBeenCalledTimes(1);
    expect(update).toHaveBeenCalledWith({
      where: { id: 'task-1' },
      data,
      include,
    });
  });

  it.each(['', ' ', '\t\n'])(
    'rejects blank title %j before writing other fields',
    (title) => {
      const { service, update } = createService();

      expect(() =>
        service.update('task-1', { title, status: 'done', assigneeId: null }),
      ).toThrow(BadRequestException);
      expect(update).not.toHaveBeenCalled();
    },
  );

  describe.each([
    {
      field: 'priority',
      values: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      fallback: 'MEDIUM',
    },
    {
      field: 'status',
      values: ['OPEN', 'IN_PROGRESS', 'DONE', 'CANCELLED'],
      fallback: 'OPEN',
    },
    {
      field: 'source',
      values: ['MANUAL', 'CVE', 'PORT', 'SUBDOMAIN', 'SSL', 'CMS'],
      fallback: 'MANUAL',
    },
  ] as const)('$field normalization', ({ field, values, fallback }) => {
    it.each(values)(
      'preserves %s and normalizes its lowercase spelling',
      async (value) => {
        const { service, update } = createService();
        for (const input of [value, value.toLowerCase()]) {
          await service.update('task-1', { [field]: input });
          expect(update).toHaveBeenLastCalledWith({
            where: { id: 'task-1' },
            data: { [field]: value },
            include,
          });
        }
        expect(update).toHaveBeenCalledTimes(2);
      },
    );

    it.each(['', 'unknown'])(
      'uses the existing fallback for explicit %j',
      async (value) => {
        const { service, update } = createService();
        await service.update('task-1', { [field]: value });
        expect(update).toHaveBeenCalledWith({
          where: { id: 'task-1' },
          data: { [field]: fallback },
          include,
        });
      },
    );
  });

  it('combines normalized edits and explicit clears in one write without mutating input', async () => {
    const { service, update } = createService();
    const patch = Object.freeze({
      title: '  Follow up  ',
      description: '  Evidence  ',
      priority: 'high',
      status: 'in_progress',
      source: 'ssl',
      websiteId: 'site-2',
      assigneeId: null,
    });
    await service.update('task-2', patch);
    expect(update).toHaveBeenCalledTimes(1);
    expect(update).toHaveBeenCalledWith({
      where: { id: 'task-2' },
      data: {
        title: 'Follow up',
        description: 'Evidence',
        priority: 'HIGH',
        status: 'IN_PROGRESS',
        source: 'SSL',
        websiteId: 'site-2',
        assigneeId: null,
      },
      include,
    });
  });

  it('does not carry previous edits into a later patch', async () => {
    const { service, update } = createService();
    await service.update('task-1', { title: 'Changed', assigneeId: null });
    await service.update('task-2', { status: 'done' });
    expect(update).toHaveBeenNthCalledWith(2, {
      where: { id: 'task-2' },
      data: { status: 'DONE' },
      include,
    });
  });

  it('propagates persistence failures instead of returning a successful edit', async () => {
    const { service, update } = createService();
    const failure = new Error('write unavailable');
    update.mockRejectedValueOnce(failure);
    await expect(service.update('task-1', { status: 'done' })).rejects.toBe(
      failure,
    );
    expect(update).toHaveBeenCalledTimes(1);
  });
});
