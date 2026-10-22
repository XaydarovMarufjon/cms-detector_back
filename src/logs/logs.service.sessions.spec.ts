import { LogsService } from './logs.service';
import { PrismaService } from '../prisma/prisma.service';

describe('LogsService session persistence contract', () => {
  const now = new Date('2026-10-22T08:00:00.000Z');
  const expiresAt = new Date('2026-10-23T08:00:00.000Z');
  let service: LogsService;
  let session: {
    create: jest.Mock;
    findUnique: jest.Mock;
    updateMany: jest.Mock;
    findMany: jest.Mock;
    update: jest.Mock;
  };

  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(now);
    session = {
      create: jest.fn(),
      findUnique: jest.fn(),
      updateMany: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
    };
    service = new LogsService({ session } as unknown as PrismaService);
  });

  afterEach(() => jest.useRealTimers());

  it('creates a session with the supplied identity, expiry and device metadata', async () => {
    const stored = { id: 'session-a' };
    session.create.mockResolvedValue(stored);
    const input = {
      userId: 'user-a',
      jti: 'token-a',
      expiresAt,
      ip: '192.0.2.10',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0',
    };
    expect(await service.createSession(input)).toBe(stored);
    expect(session.create).toHaveBeenCalledTimes(1);
    expect(session.create).toHaveBeenCalledWith({
      data: { ...input, device: 'Chrome on Windows' },
    });
    expect(input).not.toHaveProperty('device');
  });

  it.each([undefined, null])(
    'normalizes absent connection metadata (%s)',
    async (value) => {
      await service.createSession({
        userId: 'user-a',
        jti: 'token-a',
        expiresAt,
        ip: value,
        userAgent: value,
      });
      expect(session.create).toHaveBeenCalledWith({
        data: {
          userId: 'user-a',
          jti: 'token-a',
          expiresAt,
          ip: null,
          userAgent: null,
          device: null,
        },
      });
    },
  );

  it('preserves explicitly empty metadata without manufacturing a device', async () => {
    await service.createSession({
      userId: 'user-a',
      jti: 'token-a',
      expiresAt,
      ip: '',
      userAgent: '',
    });
    expect(session.create).toHaveBeenCalledWith({
      data: {
        userId: 'user-a',
        jti: 'token-a',
        expiresAt,
        ip: '',
        userAgent: '',
        device: null,
      },
    });
  });

  it.each([{ id: 'session-a' }, null])(
    'returns the exact token lookup result: %p',
    async (stored) => {
      session.findUnique.mockResolvedValue(stored);
      expect(await service.findSessionByJti('token-a')).toBe(stored);
      expect(session.findUnique).toHaveBeenCalledWith({
        where: { jti: 'token-a' },
      });
      expect(session.findUnique).toHaveBeenCalledTimes(1);
    },
  );

  it('revokes only matching, not-already-revoked token sessions', async () => {
    const result = { count: 1 };
    session.updateMany.mockResolvedValue(result);
    expect(await service.revokeByJti('token-a')).toBe(result);
    expect(session.updateMany).toHaveBeenCalledWith({
      where: { jti: 'token-a', revokedAt: null },
      data: { revokedAt: now },
    });
  });

  it('returns a zero update count without retrying or creating a session', async () => {
    const result = { count: 0 };
    session.updateMany.mockResolvedValue(result);
    expect(await service.revokeByJti('missing')).toBe(result);
    expect(session.updateMany).toHaveBeenCalledTimes(1);
    expect(session.create).not.toHaveBeenCalled();
  });

  it('extends only unrevoked token sessions and touches their activity time', async () => {
    const result = { count: 1 };
    session.updateMany.mockResolvedValue(result);
    expect(await service.extendSession('token-a', expiresAt)).toBe(result);
    expect(session.updateMany).toHaveBeenCalledWith({
      where: { jti: 'token-a', revokedAt: null },
      data: { expiresAt, lastActiveAt: now },
    });
  });

  it('does not retry or resurrect a session when extension updates no rows', async () => {
    session.updateMany.mockResolvedValue({ count: 0 });
    expect(await service.extendSession('token-a', expiresAt)).toEqual({
      count: 0,
    });
    expect(session.updateMany).toHaveBeenCalledTimes(1);
    expect(session.create).not.toHaveBeenCalled();
  });

  it('samples the current clock separately for successive operations', async () => {
    await service.revokeByJti('token-a');
    const later = new Date(now.getTime() + 1000);
    jest.setSystemTime(later);
    await service.extendSession('token-b', expiresAt);
    expect(session.updateMany).toHaveBeenNthCalledWith(1, {
      where: { jti: 'token-a', revokedAt: null },
      data: { revokedAt: now },
    });
    expect(session.updateMany).toHaveBeenNthCalledWith(2, {
      where: { jti: 'token-b', revokedAt: null },
      data: { expiresAt, lastActiveAt: later },
    });
  });

  it('lists strictly unexpired, unrevoked sessions with safe user fields and recent activity first', async () => {
    const stored = [{ id: 'session-a' }];
    session.findMany.mockResolvedValue(stored);
    expect(await service.listSessions()).toBe(stored);
    expect(session.findMany).toHaveBeenCalledWith({
      where: { revokedAt: null, expiresAt: { gt: now } },
      include: { user: { select: { id: true, username: true, role: true } } },
      orderBy: { lastActiveAt: 'desc' },
    });
  });

  it('refreshes the expiry cutoff on each listing', async () => {
    await service.listSessions();
    const later = new Date(now.getTime() + 60_000);
    jest.setSystemTime(later);
    await service.listSessions();
    expect(session.findMany).toHaveBeenLastCalledWith(
      expect.objectContaining({
        where: { revokedAt: null, expiresAt: { gt: later } },
      }),
    );
  });

  it('revokes the requested database id without rewriting other fields', async () => {
    const stored = { id: 'session-a', revokedAt: now };
    session.update.mockResolvedValue(stored);
    expect(await service.revokeSession('session-a')).toBe(stored);
    expect(session.update).toHaveBeenCalledWith({
      where: { id: 'session-a' },
      data: { revokedAt: now },
    });
  });

  it.each([
    'create',
    'lookup',
    'revoke-token',
    'extend',
    'list',
    'revoke-id',
  ] as const)(
    'propagates persistence failures without follow-up writes: %s',
    async (operation) => {
      const error = new Error('synthetic persistence failure');
      for (const mock of Object.values(session)) mock.mockRejectedValue(error);
      const actions = {
        create: () =>
          service.createSession({
            userId: 'user-a',
            jti: 'token-a',
            expiresAt,
          }),
        lookup: () => service.findSessionByJti('token-a'),
        'revoke-token': () => service.revokeByJti('token-a'),
        extend: () => service.extendSession('token-a', expiresAt),
        list: () => service.listSessions(),
        'revoke-id': () => service.revokeSession('session-a'),
      };
      await expect(actions[operation]()).rejects.toBe(error);
      expect(
        Object.values(session).reduce(
          (total, mock) => total + mock.mock.calls.length,
          0,
        ),
      ).toBe(1);
    },
  );
});
