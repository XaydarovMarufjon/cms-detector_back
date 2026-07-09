import { AlertsService } from './alerts.service';

describe('AlertsService', () => {
  function createService(existingAlert: unknown) {
    const prisma = {
      alert: {
        findUnique: jest.fn().mockResolvedValue(existingAlert),
        update: jest.fn().mockResolvedValue({}),
        create: jest.fn().mockResolvedValue({}),
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
        findMany: jest.fn().mockResolvedValue([]),
        count: jest.fn().mockResolvedValue(0),
      },
    };

    return {
      prisma,
      service: new AlertsService(prisma as any),
    };
  }

  it('rejects repeated detections for false positive alerts', async () => {
    const { prisma, service } = createService({
      id: 'alert-1',
      domain: 'example.uz',
      type: 'site_down',
      falsePositive: true,
      dismissed: true,
      falsePositiveUntil: new Date(Date.now() + 60_000),
    });

    await service.checkSiteDown('example.uz', 500, 'website-1');

    expect(prisma.alert.findUnique).toHaveBeenCalledWith({
      where: { domain_type: { domain: 'example.uz', type: 'site_down' } },
    });
    expect(prisma.alert.update).not.toHaveBeenCalled();
    expect(prisma.alert.create).not.toHaveBeenCalled();
  });

  it('stores false positive alerts for one day', async () => {
    jest.useFakeTimers().setSystemTime(new Date('2026-07-07T00:00:00.000Z'));
    const { prisma, service } = createService(null);

    await service.markFalsePositive('alert-1');

    expect(prisma.alert.update).toHaveBeenCalledWith({
      where: { id: 'alert-1' },
      data: {
        dismissed: true,
        falsePositive: true,
        falsePositiveUntil: new Date('2026-07-08T00:00:00.000Z'),
      },
    });

    jest.useRealTimers();
  });

  it('deletes expired false positive alerts before reading active alerts', async () => {
    const { prisma, service } = createService(null);

    await service.getAll();

    expect(prisma.alert.deleteMany).toHaveBeenCalledWith({
      where: {
        falsePositive: true,
        falsePositiveUntil: { lte: expect.any(Date) },
      },
    });
    expect(prisma.alert.findMany).toHaveBeenCalledWith({
      where: { dismissed: false, falsePositive: false },
      orderBy: { dueDate: 'asc' },
    });
  });
});
