import { AlertsService } from './alerts.service';
import { PrismaService } from '../prisma/prisma.service';

describe('AlertsService WHOIS calendar dates', () => {
  const prisma = {
    alert: {
      deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
      findUnique: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({}),
      update: jest.fn().mockResolvedValue({}),
    },
  };
  const service = new AlertsService(prisma as unknown as PrismaService);

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers().setSystemTime(new Date(2026, 9, 14, 12));
  });

  afterEach(() => jest.useRealTimers());

  it.each([
    '31-Apr-2026',
    '31-Jun-2026',
    '31-Sep-2026',
    '31-Nov-2025',
    '29-Feb-2026',
    '30-Feb-2024',
    '29-Feb-1900',
    '00-Oct-2026',
    '0-Oct-2026',
    '32-Oct-2026',
    '99-Jan-2026',
    '14-Abc-2026',
    'not a date',
    '',
  ])('ignores invalid date %s without touching persistence', async (input) => {
    await service.checkExpiry('example.test', input, 'website-1');

    expect(prisma.alert.deleteMany).not.toHaveBeenCalled();
    expect(prisma.alert.findUnique).not.toHaveBeenCalled();
    expect(prisma.alert.create).not.toHaveBeenCalled();
    expect(prisma.alert.update).not.toHaveBeenCalled();
  });

  it.each([
    ['14-Oct-2026', new Date(2026, 9, 14)],
    ['1-oCT-2026', new Date(2026, 9, 1)],
    ['30-Apr-2026', new Date(2026, 3, 30)],
    ['31-Dec-2025', new Date(2025, 11, 31)],
    ['29-Feb-2024', new Date(2024, 1, 29)],
    ['29-Feb-2000', new Date(2000, 1, 29)],
    ['14-Oct-0099', new Date('0099-10-14T00:00:00')],
    ['29-Feb-0000', new Date('0000-02-29T00:00:00')],
    ['2026-10-14T07:00:00+05:00', new Date('2026-10-14T02:00:00Z')],
    ['2026-10-14', new Date('2026-10-14')],
  ])('preserves the date represented by %s', async (input, dueDate) => {
    await service.checkExpiry('example.test', input, 'website-1');

    expect(prisma.alert.create).toHaveBeenCalledWith({
      data: {
        domain: 'example.test',
        type: 'expiry_urgent',
        message: expect.stringContaining(`(${input})`) as string,
        dueDate,
        dismissed: false,
        falsePositive: false,
        falsePositiveUntil: null,
        websiteId: 'website-1',
      },
    });
  });

  it.each([
    [10, 'expiry_urgent'],
    [11, 'expiry_critical'],
    [20, 'expiry_critical'],
    [21, 'expiry_warning'],
    [30, 'expiry_warning'],
  ])('preserves the %i-day alert tier', async (days, type) => {
    jest.setSystemTime(new Date(2026, 9, 1));
    const dueDate = new Date(2026, 9, 1 + days);
    const input = `${dueDate.getDate()}-Oct-2026`;
    await service.checkExpiry('example.test', input);
    expect(prisma.alert.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        type,
        dueDate,
        websiteId: null,
      }) as unknown,
    });
  });

  it('does not alert for a valid distant expiry', async () => {
    await service.checkExpiry('example.test', '31-Dec-2026');
    expect(prisma.alert.deleteMany).not.toHaveBeenCalled();
    expect(prisma.alert.create).not.toHaveBeenCalled();
  });
});
