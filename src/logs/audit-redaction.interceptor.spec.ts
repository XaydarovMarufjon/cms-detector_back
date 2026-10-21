import type { ExecutionContext } from '@nestjs/common';
import { lastValueFrom, of, throwError } from 'rxjs';
import { AuditInterceptor } from './audit.interceptor';
import type { LogsService } from './logs.service';

type AuditInput = Parameters<LogsService['writeAudit']>[0];
type JsonRecord = Record<string, unknown>;

// These are synthetic fixtures, never real credentials or requests.
const SYNTHETIC_VALUE = 'synthetic-sensitive-fixture';

function createHarness(body: unknown) {
  const writeAudit = jest.fn<Promise<unknown>, [AuditInput]>();
  writeAudit.mockResolvedValue({});
  const interceptor = new AuditInterceptor({
    writeAudit,
  } as unknown as LogsService);
  const request = {
    method: 'PATCH',
    originalUrl: '/api/settings/example',
    url: '/api/settings/example',
    path: '/api/settings/example',
    headers: {},
    params: { id: 'example' },
    user: { id: 'user-example', username: 'fixture-user' },
    body,
  };
  const context = {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  const result = { ok: true };
  const handle = jest.fn(() => of(result));

  return {
    interceptor,
    context,
    request,
    result,
    handle,
    writeAudit,
    loggedBody: () =>
      (writeAudit.mock.calls[0][0].metadata as { body: unknown }).body,
    run: () => lastValueFrom(interceptor.intercept(context, { handle })),
  };
}

describe('AuditInterceptor body redaction', () => {
  it.each([
    'password',
    'PASSWORD',
    'newPassword',
    'token',
    'refreshToken',
    'secret',
    'clientSecret',
    'apiKey',
    'APIKEY',
  ])(
    'masks nested %s fields using the existing case-insensitive policy',
    async (key) => {
      const harness = createHarness({
        settings: { account: { [key]: SYNTHETIC_VALUE, label: 'keep me' } },
      });

      await harness.run();

      expect(harness.loggedBody()).toEqual({
        settings: { account: { [key]: '[redacted]', label: 'keep me' } },
      });
    },
  );

  it('masks nested array records and preserves non-sensitive array values', async () => {
    const harness = createHarness({
      connections: [
        { password: SYNTHETIC_VALUE, label: 'first' },
        [{ token: SYNTHETIC_VALUE }, false, 0, null, 'ordinary'],
        { options: { apiKey: SYNTHETIC_VALUE }, enabled: true },
      ],
    });

    await harness.run();

    expect(harness.loggedBody()).toEqual({
      connections: [
        { password: '[redacted]', label: 'first' },
        [{ token: '[redacted]' }, false, 0, null, 'ordinary'],
        { options: { apiKey: '[redacted]' }, enabled: true },
      ],
    });
  });

  it('keeps a top-level array as an array while masking its nested fields', async () => {
    const harness = createHarness([
      { password: SYNTHETIC_VALUE },
      [{ clientSecret: SYNTHETIC_VALUE }],
    ]);

    await harness.run();

    expect(Array.isArray(harness.loggedBody())).toBe(true);
    expect(harness.loggedBody()).toEqual([
      { password: '[redacted]' },
      [{ clientSecret: '[redacted]' }],
    ]);
  });

  it('redacts the entire value of a matching key, regardless of its shape', async () => {
    const harness = createHarness({
      password: { value: SYNTHETIC_VALUE },
      token: [SYNTHETIC_VALUE],
      secret: null,
      apiKey: 0,
    });

    await harness.run();

    expect(harness.loggedBody()).toEqual({
      password: '[redacted]',
      token: '[redacted]',
      secret: '[redacted]',
      apiKey: '[redacted]',
    });
  });

  it.each([null, undefined, false, 0, '', 'ordinary text'])(
    'preserves the non-object body %p',
    async (body) => {
      const harness = createHarness(body);
      await harness.run();
      expect(harness.loggedBody()).toBe(body);
    },
  );

  it('does not mutate frozen request objects or arrays', async () => {
    const account = Object.freeze({ password: SYNTHETIC_VALUE, label: 'keep' });
    const accounts = Object.freeze([account]);
    const body = Object.freeze({ accounts });
    const harness = createHarness(body);

    await expect(harness.run()).resolves.toBe(harness.result);

    expect(harness.request.body).toBe(body);
    expect(account.password).toBe(SYNTHETIC_VALUE);
    const logged = harness.loggedBody() as { accounts: JsonRecord[] };
    expect(logged).not.toBe(body);
    expect(logged.accounts).not.toBe(accounts);
    expect(logged.accounts[0]).not.toBe(account);
    expect(logged).toEqual({
      accounts: [{ password: '[redacted]', label: 'keep' }],
    });
  });

  it('handles own special property names without changing object prototypes', async () => {
    const body: unknown = JSON.parse(
      '{"__proto__":{"password":"synthetic-sensitive-fixture"},"constructor":{"token":"synthetic-sensitive-fixture"},"prototype":{"secret":"synthetic-sensitive-fixture"}}',
    );
    const harness = createHarness(body);

    await harness.run();

    const logged = harness.loggedBody() as JsonRecord;
    expect(Object.getPrototypeOf(logged)).toBe(Object.prototype);
    expect(Object.hasOwn(logged, '__proto__')).toBe(true);
    expect(logged['__proto__']).toEqual({ password: '[redacted]' });
    expect(logged['constructor']).toEqual({ token: '[redacted]' });
    expect(logged['prototype']).toEqual({ secret: '[redacted]' });
  });

  it('redacts shared objects without retaining the original reference', async () => {
    const shared = { token: SYNTHETIC_VALUE };
    const harness = createHarness({ first: shared, second: shared });

    await harness.run();

    const logged = harness.loggedBody() as JsonRecord;
    expect(logged['first']).toEqual({ token: '[redacted]' });
    expect(logged['second']).toBe(logged['first']);
    expect(logged['first']).not.toBe(shared);
    expect(shared.token).toBe(SYNTHETIC_VALUE);
  });

  it('does not recurse forever if middleware adds an object cycle', async () => {
    const body: JsonRecord = { password: SYNTHETIC_VALUE };
    body['self'] = body;
    const harness = createHarness(body);

    await expect(harness.run()).resolves.toBe(harness.result);

    const logged = harness.loggedBody() as JsonRecord;
    expect(logged['password']).toBe('[redacted]');
    expect(logged['self']).toBe(logged);
    expect(logged).not.toBe(body);
    expect(body['password']).toBe(SYNTHETIC_VALUE);
  });

  it('preserves Date values added by middleware without sharing mutable references', async () => {
    const date = new Date('2026-10-21T00:00:00.000Z');
    const harness = createHarness({
      options: { date, password: SYNTHETIC_VALUE },
    });

    await harness.run();

    const logged = harness.loggedBody() as { options: JsonRecord };
    expect(logged.options['date']).toEqual(date);
    expect(logged.options['date']).not.toBe(date);
    expect(logged.options['password']).toBe('[redacted]');
  });

  it('preserves sparse array length and holes without exposing nested fields', async () => {
    const items: unknown[] = new Array<unknown>(4);
    items[1] = { password: SYNTHETIC_VALUE };
    const harness = createHarness({ items });

    await harness.run();

    const logged = (harness.loggedBody() as { items: unknown[] }).items;
    expect(logged).toHaveLength(4);
    expect(Object.keys(logged)).toEqual(['1']);
    expect(logged[1]).toEqual({ password: '[redacted]' });
    expect(items[1]).toEqual({ password: SYNTHETIC_VALUE });
  });

  it('handles array cycles introduced by middleware without mutating the input', async () => {
    const items: unknown[] = [{ token: SYNTHETIC_VALUE }];
    items.push(items);
    const harness = createHarness(items);

    await expect(harness.run()).resolves.toBe(harness.result);

    const logged = harness.loggedBody() as unknown[];
    expect(logged[0]).toEqual({ token: '[redacted]' });
    expect(logged[1]).toBe(logged);
    expect(items[0]).toEqual({ token: SYNTHETIC_VALUE });
  });

  it('handles a deeply nested body without exhausting the call stack', async () => {
    const body: JsonRecord = {};
    let leaf = body;
    for (let depth = 0; depth < 12_000; depth++) {
      const next: JsonRecord = {};
      leaf['child'] = next;
      leaf = next;
    }
    leaf['password'] = SYNTHETIC_VALUE;
    const harness = createHarness(body);

    await expect(harness.run()).resolves.toBe(harness.result);

    let logged = harness.loggedBody() as JsonRecord;
    for (let depth = 0; depth < 12_000; depth++) {
      logged = logged['child'] as JsonRecord;
    }
    expect(logged['password']).toBe('[redacted]');
    expect(leaf['password']).toBe(SYNTHETIC_VALUE);
  });

  it('preserves successful handler output and audit metadata', async () => {
    const harness = createHarness({ options: { password: SYNTHETIC_VALUE } });

    await expect(harness.run()).resolves.toBe(harness.result);

    expect(harness.handle).toHaveBeenCalledTimes(1);
    expect(harness.writeAudit).toHaveBeenCalledTimes(1);
    expect(harness.writeAudit).toHaveBeenCalledWith({
      userId: 'user-example',
      username: 'fixture-user',
      action: 'patch.settings.example',
      method: 'PATCH',
      path: '/api/settings/example',
      targetId: 'example',
      ip: undefined,
      userAgent: undefined,
      metadata: {
        params: { id: 'example' },
        body: { options: { password: '[redacted]' } },
        durationMs: expect.any(Number) as unknown,
        status: 'ok',
      },
    });
  });

  it('redacts failed requests and rethrows the same handler error', async () => {
    const harness = createHarness({ options: { password: SYNTHETIC_VALUE } });
    const failure = { status: 400, message: 'synthetic handler failure' };
    const handle = jest.fn(() => throwError(() => failure));

    await expect(
      lastValueFrom(harness.interceptor.intercept(harness.context, { handle })),
    ).rejects.toBe(failure);

    expect(harness.writeAudit).toHaveBeenCalledTimes(1);
    expect(harness.writeAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'patch.error',
        metadata: expect.objectContaining({
          status: 400,
          body: { options: { password: '[redacted]' } },
        }) as unknown,
      }),
    );
  });

  it('preserves the handler error when the audit write also rejects', async () => {
    const harness = createHarness({ options: { token: SYNTHETIC_VALUE } });
    harness.writeAudit.mockRejectedValue(
      new Error('synthetic storage failure'),
    );
    const failure = new Error('synthetic handler failure');
    const handle = () => throwError(() => failure);

    await expect(
      lastValueFrom(harness.interceptor.intercept(harness.context, { handle })),
    ).rejects.toBe(failure);

    expect(harness.loggedBody()).toEqual({ options: { token: '[redacted]' } });
  });

  it('does not replace successful output when the audit write rejects', async () => {
    const harness = createHarness({ options: { token: SYNTHETIC_VALUE } });
    harness.writeAudit.mockRejectedValue(
      new Error('synthetic storage failure'),
    );

    await expect(harness.run()).resolves.toBe(harness.result);

    expect(harness.loggedBody()).toEqual({ options: { token: '[redacted]' } });
  });
});
