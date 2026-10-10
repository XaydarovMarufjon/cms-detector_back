import type { PrismaService } from '../prisma/prisma.service';
import { SystemStatusService } from './system-status.service';

type StatusFilter = { in?: string[]; notIn?: string[] };

describe('SystemStatusService open task count', () => {
  const now = new Date('2026-10-10T08:00:00.000Z');
  const since24h = new Date('2026-10-09T08:00:00.000Z');

  function createService(statuses: string[] = []) {
    const prisma = {
      $queryRaw: jest.fn().mockResolvedValue([{ '?column?': 1 }]),
      website: { count: jest.fn().mockResolvedValue(3) },
      scanResult: {
        count: jest.fn().mockResolvedValue(0),
        findMany: jest.fn().mockResolvedValue([]),
      },
      nucleiResult: { count: jest.fn().mockResolvedValue(0) },
      subdomainCache: { count: jest.fn().mockResolvedValue(0) },
      portScanResult: { count: jest.fn().mockResolvedValue(0) },
      bulkScanJob: {
        count: jest.fn().mockResolvedValue(0),
        findMany: jest.fn().mockResolvedValue([]),
      },
      session: { count: jest.fn().mockResolvedValue(0) },
      auditLog: {
        count: jest.fn().mockResolvedValue(0),
        findMany: jest.fn().mockResolvedValue([]),
      },
      securityTask: {
        // Model only membership filtering; this is not a database integration test.
        count: jest.fn(({ where }: { where: { status: StatusFilter } }) =>
          Promise.resolve(
            statuses.filter(
              (status) =>
                (!where.status.in || where.status.in.includes(status)) &&
                (!where.status.notIn || !where.status.notIn.includes(status)),
            ).length,
          ),
        ),
      },
      autoScanState: { findUnique: jest.fn().mockResolvedValue(null) },
      threatFeed: { findMany: jest.fn().mockResolvedValue([]) },
    };
    const service = new SystemStatusService(prisma as unknown as PrismaService);

    // Exercise the database snapshot in isolation, avoiding host/network probes.
    const snapshot = () => service['getDatabaseSnapshot'](now, since24h);
    return { prisma, snapshot };
  }

  it('counts only actionable tasks in a mixed status dataset', async () => {
    const { prisma, snapshot } = createService([
      'OPEN',
      'OPEN',
      'IN_PROGRESS',
      'CANCELLED',
      'DONE',
      'CLOSED',
      'RESOLVED',
    ]);

    const result = await snapshot();

    expect(result.scans.openTasks).toBe(3);
    expect(prisma.securityTask.count).toHaveBeenCalledTimes(1);
    expect(prisma.securityTask.count).toHaveBeenCalledWith({
      where: { status: { in: ['OPEN', 'IN_PROGRESS'] } },
    });
    expect(result.health.ok).toBe(true);
    expect(result.database.websitesTotal).toBe(3);
  });

  it.each<[string, number]>([
    ['OPEN', 1],
    ['IN_PROGRESS', 1],
    ['CANCELLED', 0],
    ['DONE', 0],
    ['CLOSED', 0],
    ['RESOLVED', 0],
    ['UNKNOWN', 0],
  ])('counts %s tasks as %i open tasks', async (status, expected) => {
    const { snapshot } = createService([status]);

    expect((await snapshot()).scans.openTasks).toBe(expected);
  });

  it('returns zero for an empty task dataset', async () => {
    const { snapshot } = createService();

    expect((await snapshot()).scans.openTasks).toBe(0);
  });

  it('forwards the database count without recomputing it from unrelated data', async () => {
    const { prisma, snapshot } = createService();
    prisma.securityTask.count.mockResolvedValue(42);

    expect((await snapshot()).scans.openTasks).toBe(42);
  });

  it('keeps the existing unhealthy fallback when counting tasks fails', async () => {
    const { prisma, snapshot } = createService(['OPEN']);
    prisma.securityTask.count.mockRejectedValue(new Error('count unavailable'));

    const result = await snapshot();

    expect(result.health.ok).toBe(false);
    expect(result.database.ok).toBe(false);
    expect(result.scans.openTasks).toBe(0);
    expect(result.issues).toEqual([
      expect.objectContaining({
        source: 'database',
        severity: 'error',
        detail: 'count unavailable',
        at: now.toISOString(),
      }),
    ]);
  });
});
