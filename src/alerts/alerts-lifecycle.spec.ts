import { AlertsService } from './alerts.service';
import { PrismaService } from '../prisma/prisma.service';

describe('AlertsService alert lifecycle', () => {
  const now = new Date('2026-10-19T08:00:00.000Z');

  function setup() {
    const alert = {
      deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
      findUnique: jest.fn().mockResolvedValue(null),
      findMany: jest.fn().mockResolvedValue([]),
      count: jest.fn().mockResolvedValue(0),
      create: jest.fn().mockResolvedValue({ id: 'created' }),
      update: jest.fn().mockResolvedValue({ id: 'updated' }),
    };
    return {
      alert,
      service: new AlertsService({ alert } as unknown as PrismaService),
    };
  }

  beforeEach(() => jest.useFakeTimers().setSystemTime(now));
  afterEach(() => jest.useRealTimers());

  const reads = ['getAll', 'getCount', 'getFalsePositive'] as const;

  it.each(reads)(
    'waits for cleanup before %s and uses the current expiry cutoff',
    async (method) => {
      const { alert, service } = setup();
      let release!: (value: { count: number }) => void;
      alert.deleteMany.mockReturnValueOnce(
        new Promise<{ count: number }>((resolve) => {
          release = resolve;
        }),
      );
      const pending = service[method]();
      try {
        await Promise.resolve();
        expect(alert.deleteMany).toHaveBeenCalledTimes(1);
        expect(alert.deleteMany).toHaveBeenCalledWith({
          where: { falsePositive: true, falsePositiveUntil: { lte: now } },
        });
        expect(alert.findMany).not.toHaveBeenCalled();
        expect(alert.count).not.toHaveBeenCalled();
      } finally {
        release({ count: 2 });
        await pending;
      }
      expect(
        alert.findMany.mock.calls.length + alert.count.mock.calls.length,
      ).toBe(1);
    },
  );

  it.each(reads)(
    'propagates cleanup failure without reading in %s',
    async (method) => {
      const { alert, service } = setup();
      const failure = new Error('cleanup unavailable');
      alert.deleteMany.mockRejectedValueOnce(failure);
      await expect(service[method]()).rejects.toBe(failure);
      expect(alert.findMany).not.toHaveBeenCalled();
      expect(alert.count).not.toHaveBeenCalled();
    },
  );

  it.each([
    ['getAll', { dismissed: false, falsePositive: false }, { dueDate: 'asc' }],
    ['getFalsePositive', { falsePositive: true }, { dueDate: 'desc' }],
  ] as const)(
    'preserves %s visibility, ordering and returned records',
    async (method, where, orderBy) => {
      const { alert, service } = setup();
      const records = [{ id: 'one' }, { id: 'two' }];
      alert.findMany.mockResolvedValueOnce(records);
      await expect(service[method]()).resolves.toBe(records);
      expect(alert.findMany).toHaveBeenCalledTimes(1);
      expect(alert.findMany).toHaveBeenCalledWith({ where, orderBy });
    },
  );

  it('counts only visible active alerts and forwards the stored count', async () => {
    const { alert, service } = setup();
    alert.count.mockResolvedValueOnce(7);
    await expect(service.getCount()).resolves.toBe(7);
    expect(alert.count).toHaveBeenCalledWith({
      where: { dismissed: false, falsePositive: false },
    });
  });

  it.each(reads)(
    'propagates a read failure in %s after cleanup',
    async (method) => {
      const { alert, service } = setup();
      const failure = new Error('read unavailable');
      (method === 'getCount'
        ? alert.count
        : alert.findMany
      ).mockRejectedValueOnce(failure);
      await expect(service[method]()).rejects.toBe(failure);
      expect(alert.deleteMany).toHaveBeenCalledTimes(1);
    },
  );

  it('refreshes the cleanup cutoff on each operation', async () => {
    const { alert, service } = setup();
    await service.getAll();
    const later = new Date(now.getTime() + 60_000);
    jest.setSystemTime(later);
    await service.getCount();
    expect(alert.deleteMany.mock.calls).toEqual([
      [{ where: { falsePositive: true, falsePositiveUntil: { lte: now } } }],
      [{ where: { falsePositive: true, falsePositiveUntil: { lte: later } } }],
    ]);
  });

  it.each([
    ['dismiss', { dismissed: true }],
    [
      'restore',
      { dismissed: false, falsePositive: false, falsePositiveUntil: null },
    ],
  ] as const)(
    '%s changes only its lifecycle fields and returns the saved record',
    async (method, data) => {
      const { alert, service } = setup();
      const saved = { id: 'selected-alert', ...data };
      alert.update.mockResolvedValueOnce(saved);
      await expect(service[method]('selected-alert')).resolves.toBe(saved);
      expect(alert.update).toHaveBeenCalledTimes(1);
      expect(alert.update).toHaveBeenCalledWith({
        where: { id: 'selected-alert' },
        data,
      });
      expect(alert.deleteMany).not.toHaveBeenCalled();
      expect(alert.create).not.toHaveBeenCalled();
    },
  );

  it.each(['dismiss', 'restore', 'markFalsePositive'] as const)(
    '%s propagates persistence errors',
    async (method) => {
      const { alert, service } = setup();
      const failure = new Error('write unavailable');
      alert.update.mockRejectedValueOnce(failure);
      await expect(service[method]('selected-alert')).rejects.toBe(failure);
      expect(alert.update).toHaveBeenCalledTimes(1);
      expect(alert.create).not.toHaveBeenCalled();
    },
  );

  it('restarts the 24-hour suppression window when marked again', async () => {
    const { alert, service } = setup();
    await service.markFalsePositive('selected-alert');
    jest.setSystemTime(new Date(now.getTime() + 3_600_000));
    await service.markFalsePositive('selected-alert');
    expect(alert.update.mock.calls).toEqual(
      [0, 3_600_000].map((offset) => [
        {
          where: { id: 'selected-alert' },
          data: {
            dismissed: true,
            falsePositive: true,
            falsePositiveUntil: new Date(now.getTime() + offset + 86_400_000),
          },
        },
      ]),
    );
  });

  it.each([undefined, 'website-2'])(
    'reopens an ordinary dismissed recurrence with website %s',
    async (websiteId) => {
      const { alert, service } = setup();
      alert.findUnique.mockResolvedValueOnce({
        id: 'old',
        dismissed: true,
        falsePositive: false,
      });
      await service.checkSiteDown('example.test', 503, websiteId);
      expect(alert.findUnique).toHaveBeenCalledWith({
        where: { domain_type: { domain: 'example.test', type: 'site_down' } },
      });
      expect(alert.update).toHaveBeenCalledWith({
        where: { domain_type: { domain: 'example.test', type: 'site_down' } },
        data: {
          message: 'example.test: Sayt ishlamayapti (HTTP 503)',
          dueDate: new Date(now.getTime() + 7 * 86_400_000),
          dismissed: false,
          websiteId: websiteId ?? null,
        },
      });
      expect(alert.create).not.toHaveBeenCalled();
    },
  );

  it('waits for cleanup before looking up a repeated detection', async () => {
    const { alert, service } = setup();
    let release!: (value: { count: number }) => void;
    alert.deleteMany.mockReturnValueOnce(
      new Promise<{ count: number }>((resolve) => {
        release = resolve;
      }),
    );
    const pending = service.checkSiteDown('example.test', 503);
    try {
      await Promise.resolve();
      expect(alert.findUnique).not.toHaveBeenCalled();
      expect(alert.create).not.toHaveBeenCalled();
      expect(alert.update).not.toHaveBeenCalled();
    } finally {
      release({ count: 1 });
      await pending;
    }
    expect(alert.findUnique).toHaveBeenCalledTimes(1);
    expect(alert.create).toHaveBeenCalledTimes(1);
  });

  it.each(['deleteMany', 'findUnique', 'create', 'update'] as const)(
    'propagates detection %s failures without later writes',
    async (method) => {
      const { alert, service } = setup();
      const failure = new Error(`${method} unavailable`);
      if (method === 'update')
        alert.findUnique.mockResolvedValueOnce({ falsePositive: false });
      alert[method].mockRejectedValueOnce(failure);
      await expect(service.checkSiteDown('example.test', 503)).rejects.toBe(
        failure,
      );
      if (method === 'deleteMany')
        expect(alert.findUnique).not.toHaveBeenCalled();
      expect(alert.create).toHaveBeenCalledTimes(method === 'create' ? 1 : 0);
      expect(alert.update).toHaveBeenCalledTimes(method === 'update' ? 1 : 0);
    },
  );
});
