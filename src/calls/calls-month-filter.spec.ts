import { BadRequestException } from '@nestjs/common';
import type { PrismaService } from '../prisma/prisma.service';
import { CallsService } from './calls.service';

describe('CallsService month filters', () => {
  const findMany = jest.fn();
  let service: CallsService;

  beforeEach(() => {
    findMany.mockReset().mockResolvedValue([]);
    service = new CallsService({
      call: { findMany },
    } as unknown as PrismaService);
  });

  it.each(['2026-00', '2026-13', '2026-99'])(
    'rejects out-of-range month %s before querying',
    (month) => {
      expect(() => service.list({ month })).toThrow(BadRequestException);
      expect(findMany).not.toHaveBeenCalled();
    },
  );

  it.each([
    ['0000-02', '0000-03'],
    ['0001-01', '0001-02'],
    ['0099-12', '0100-01'],
    ['0100-02', '0100-03'],
    ['2024-02', '2024-03'],
    ['2011-04', '2011-05'], // Asia/Amman skipped midnight on April 1.
    ['2026-01', '2026-02'],
    ['2026-03', '2026-04'],
    ['2026-10', '2026-11'],
    ['2026-11', '2026-12'],
    ['2026-12', '2027-01'],
    ['9999-12', '+010000-01'],
  ])('uses literal local calendar boundaries for %s', async (month, next) => {
    const rows = [{ id: 'call-1' }];
    findMany.mockResolvedValue(rows);
    const input = { month, category: 'Telegram' };
    await expect(service.list(input)).resolves.toBe(rows);
    expect(findMany).toHaveBeenCalledTimes(1);
    expect(findMany).toHaveBeenCalledWith({
      where: {
        category: 'Telegram',
        createdAt: {
          gte: new Date(`${month}-01T00:00:00`),
          lt: new Date(`${next}-01T00:00:00`),
        },
      },
      orderBy: { createdAt: 'desc' },
    });
    expect(input).toEqual({ month, category: 'Telegram' });
  });

  it('keeps month precedence over explicit date bounds', async () => {
    await service.list({
      month: '2026-10',
      from: '2026-01-01',
      to: '2026-12-31',
    });
    expect(findMany).toHaveBeenCalledWith({
      where: {
        createdAt: {
          gte: new Date('2026-10-01T00:00:00'),
          lt: new Date('2026-11-01T00:00:00'),
        },
      },
      orderBy: { createdAt: 'desc' },
    });
  });

  it('does not fall back to date bounds for an out-of-range month', () => {
    expect(() =>
      service.list({ month: '2026-13', from: '2026-01-01' }),
    ).toThrow(BadRequestException);
    expect(findMany).not.toHaveBeenCalled();
  });

  it.each(['2026-1', 'not-a-month', ' 2026-10 ', '2026-10-01'])(
    'preserves the existing no-date-filter fallback for malformed %j',
    async (month) => {
      await service.list({ month, category: 'CSEC', from: '2026-01-01' });
      expect(findMany).toHaveBeenCalledWith({
        where: { category: 'CSEC' },
        orderBy: { createdAt: 'desc' },
      });
    },
  );

  it('keeps empty month optional', async () => {
    await service.list({ month: '' });
    expect(findMany).toHaveBeenCalledWith({
      where: {},
      orderBy: { createdAt: 'desc' },
    });
  });

  it('propagates query failures for valid months', async () => {
    const failure = new Error('query failed');
    findMany.mockRejectedValue(failure);
    await expect(service.list({ month: '2026-10' })).rejects.toBe(failure);
  });
});
