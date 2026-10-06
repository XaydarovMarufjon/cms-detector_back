import { PrismaService } from '../prisma/prisma.service';
import { CallsService } from './calls.service';

describe('CallsService date filters', () => {
  function createService() {
    const prisma = {
      call: { findMany: jest.fn().mockResolvedValue([]) },
    };
    return {
      prisma,
      service: new CallsService(prisma as unknown as PrismaService),
    };
  }

  afterEach(() => {
    jest.useRealTimers();
  });

  it.each([
    ['2026-03-08', '2026-03-09'], // America/New_York: spring forward
    ['2026-11-01', '2026-11-02'], // America/New_York: fall back
    ['2026-03-29', '2026-03-30'], // Europe/Berlin: spring forward
    ['2026-10-25', '2026-10-26'], // Europe/Berlin: fall back
    ['2026-04-05', '2026-04-06'], // Australia/Lord_Howe: 30-minute fall back
    ['2026-10-04', '2026-10-05'], // Australia/Lord_Howe: 30-minute spring forward
    ['2026-10-06', '2026-10-07'], // Ordinary day
    ['2024-02-28', '2024-02-29'], // Leap day
    ['2024-02-29', '2024-03-01'], // Month rollover
    ['2026-12-31', '2027-01-01'], // Year rollover
    ['0099-12-31', '0100-01-01'], // Preserve literal years below 100
  ])(
    'ends the inclusive date %s at the next local midnight',
    async (to, next) => {
      const { prisma, service } = createService();

      await service.list({ from: to, to });

      expect(prisma.call.findMany).toHaveBeenCalledWith({
        where: {
          createdAt: {
            gte: new Date(`${to}T00:00:00`),
            lt: new Date(`${next}T00:00:00`),
          },
        },
        orderBy: { createdAt: 'desc' },
      });
    },
  );

  it('preserves the start and category for a multi-day range', async () => {
    const { prisma, service } = createService();

    await service.list({
      from: '2026-03-01',
      to: '2026-03-08',
      category: 'Telegram',
    });

    expect(prisma.call.findMany).toHaveBeenCalledWith({
      where: {
        category: 'Telegram',
        createdAt: {
          gte: new Date('2026-03-01T00:00:00'),
          lt: new Date('2026-03-09T00:00:00'),
        },
      },
      orderBy: { createdAt: 'desc' },
    });
  });

  it('uses the epoch start when only an end date is supplied', async () => {
    const { prisma, service } = createService();

    await service.list({ to: '2026-11-01' });

    expect(prisma.call.findMany).toHaveBeenCalledWith({
      where: {
        createdAt: {
          gte: new Date(0),
          lt: new Date('2026-11-02T00:00:00'),
        },
      },
      orderBy: { createdAt: 'desc' },
    });
  });

  it('preserves the existing now-plus-24-hours fallback without an end date', async () => {
    const now = new Date('2026-03-08T05:00:00Z');
    jest.useFakeTimers().setSystemTime(now);
    const { prisma, service } = createService();

    await service.list({ from: '2026-03-01' });

    expect(prisma.call.findMany).toHaveBeenCalledWith({
      where: {
        createdAt: {
          gte: new Date('2026-03-01T00:00:00'),
          lt: new Date('2026-03-09T05:00:00Z'),
        },
      },
      orderBy: { createdAt: 'desc' },
    });
  });

  it('keeps the month filter precedence and local calendar boundaries', async () => {
    const { prisma, service } = createService();

    await service.list({
      month: '2026-03',
      from: '2026-03-08',
      to: '2026-03-08',
    });

    expect(prisma.call.findMany).toHaveBeenCalledWith({
      where: {
        createdAt: {
          gte: new Date('2026-03-01T00:00:00'),
          lt: new Date('2026-04-01T00:00:00'),
        },
      },
      orderBy: { createdAt: 'desc' },
    });
  });

  it('does not add a date filter when no dates are supplied', async () => {
    const { prisma, service } = createService();

    await service.list({ category: 'Telegram' });

    expect(prisma.call.findMany).toHaveBeenCalledWith({
      where: { category: 'Telegram' },
      orderBy: { createdAt: 'desc' },
    });
  });
});
