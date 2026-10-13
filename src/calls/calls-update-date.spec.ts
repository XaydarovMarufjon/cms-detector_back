import { BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CallsService } from './calls.service';

describe('CallsService update date validation', () => {
  const findUnique = jest.fn();
  const update = jest.fn();
  const prisma = { call: { findUnique, update } };
  let service: CallsService;

  beforeEach(() => {
    jest.resetAllMocks();
    findUnique.mockResolvedValue({ id: 'call-1' });
    update.mockResolvedValue({ id: 'call-1', note: 'saved' });
    service = new CallsService(prisma as unknown as PrismaService);
  });

  it.each([
    null,
    false,
    true,
    0,
    1,
    1700000000000,
    [],
    ['2026-10-13'],
    ['2026', '10', '13'],
    {},
  ])('rejects non-string JSON dates (%j) without writing', async (value) => {
    await expect(
      service.update('call-1', { createdAt: value as unknown as string }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(update).not.toHaveBeenCalled();
  });

  it.each(['', ' ', 'not-a-date', '2026-13-01'])(
    'rejects invalid string dates (%j) without writing',
    async (createdAt) => {
      await expect(
        service.update('call-1', { createdAt }),
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(update).not.toHaveBeenCalled();
    },
  );

  it.each([
    '2026-10-13',
    '2026-10-13T10:20:30Z',
    '2026-10-13T10:20:30+05:00',
    '2024-02-29T23:59:59.123Z',
    'October 13, 2026',
  ])('preserves accepted string dates (%s)', async (createdAt) => {
    await expect(service.update('call-1', { createdAt })).resolves.toEqual({
      id: 'call-1',
      note: 'saved',
    });
    expect(update).toHaveBeenCalledWith({
      where: { id: 'call-1' },
      data: {
        phoneNumber: undefined,
        category: undefined,
        note: undefined,
        createdAt: new Date(createdAt),
      },
    });
  });

  it('leaves the timestamp unchanged when omitted and preserves other edits', async () => {
    await service.update('call-1', {
      phoneNumber: ' 123 ',
      category: 'CSEC',
      note: ' edited ',
    });
    expect(update).toHaveBeenCalledWith({
      where: { id: 'call-1' },
      data: {
        phoneNumber: '123',
        category: 'CSEC',
        note: 'edited',
        createdAt: undefined,
      },
    });
  });

  it('rejects the entire patch when its date is invalid', async () => {
    await expect(
      service.update('call-1', {
        note: 'must not be saved',
        createdAt: null as unknown as string,
      }),
    ).rejects.toMatchObject({ status: 400 });
    expect(update).not.toHaveBeenCalled();
  });

  it('preserves not-found precedence over date validation', async () => {
    findUnique.mockResolvedValue(null);
    await expect(
      service.update('missing', { createdAt: null as unknown as string }),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(findUnique).toHaveBeenCalledWith({ where: { id: 'missing' } });
    expect(update).not.toHaveBeenCalled();
  });

  it('propagates a persistence failure for a valid date', async () => {
    const failure = new Error('write failed');
    update.mockRejectedValue(failure);
    await expect(
      service.update('call-1', { createdAt: '2026-10-13' }),
    ).rejects.toBe(failure);
  });
});
