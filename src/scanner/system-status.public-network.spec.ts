import axios from 'axios';
import { PrismaService } from '../prisma/prisma.service';
import { SystemStatusService } from './system-status.service';

jest.mock('axios');

describe('SystemStatusService public-network cache', () => {
  const start = new Date('2026-10-15T08:00:00.000Z').getTime();
  const hour = 60 * 60 * 1000;
  const retryDelay = 5 * 60 * 1000;
  const get = jest.spyOn(axios, 'get');
  const network = {
    ip: '203.0.113.10',
    isp: 'Example ISP',
    country: 'Example country',
    city: 'Example city',
    error: null,
  };

  function createService() {
    // Exercise only the cache helper; no database or host-resource probes run.
    const service = new SystemStatusService({} as PrismaService);
    return () => service['getPublicNetwork']();
  }

  function respond(ip = network.ip) {
    get.mockResolvedValueOnce({
      data: {
        success: true,
        ip,
        connection: { isp: network.isp, org: 'Example organization' },
        country: network.country,
        city: network.city,
      },
    });
  }

  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(start);
    get.mockReset();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('maps a successful lookup and retains the bounded HTTP timeout', async () => {
    const lookup = createService();
    respond();

    expect(await lookup()).toEqual(network);
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith('https://ipwho.is/', { timeout: 3500 });
  });

  it('uses the provider organization when its ISP is missing', async () => {
    const lookup = createService();
    get.mockResolvedValueOnce({
      data: { ip: network.ip, connection: { org: 'Example organization' } },
    });

    expect(await lookup()).toEqual({
      ip: network.ip,
      isp: 'Example organization',
      country: null,
      city: null,
      error: null,
    });
  });

  it('represents absent optional location and connection fields as null', async () => {
    const lookup = createService();
    get.mockResolvedValueOnce({ data: { success: true, ip: network.ip } });

    expect(await lookup()).toEqual({
      ip: network.ip,
      isp: null,
      country: null,
      city: null,
      error: null,
    });
  });

  it('reuses successful data throughout the hour without another request', async () => {
    const lookup = createService();
    respond();
    await lookup();

    expect(await lookup()).toEqual(network);
    jest.setSystemTime(start + hour - 1);
    expect(await lookup()).toEqual(network);
    expect(get).toHaveBeenCalledTimes(1);
  });

  it.each([hour, hour + 1])(
    'refreshes successful data after %i milliseconds',
    async (elapsed) => {
      const lookup = createService();
      respond();
      await lookup();
      respond('203.0.113.20');

      jest.setSystemTime(start + elapsed);

      expect(await lookup()).toEqual({ ...network, ip: '203.0.113.20' });
      expect(get).toHaveBeenCalledTimes(2);
    },
  );

  it('starts a new one-hour cache window after a successful refresh', async () => {
    const lookup = createService();
    respond();
    await lookup();
    respond('203.0.113.20');
    jest.setSystemTime(start + hour);
    await lookup();

    jest.setSystemTime(start + 2 * hour - 1);
    expect(await lookup()).toEqual({ ...network, ip: '203.0.113.20' });
    expect(get).toHaveBeenCalledTimes(2);

    respond('203.0.113.30');
    jest.setSystemTime(start + 2 * hour);
    expect(await lookup()).toEqual({ ...network, ip: '203.0.113.30' });
    expect(get).toHaveBeenCalledTimes(3);
  });

  it('caches an HTTP failure for five minutes without retrying early', async () => {
    const lookup = createService();
    get.mockRejectedValueOnce(new Error('request timed out'));
    const failure = {
      ip: null,
      isp: null,
      country: null,
      city: null,
      error: 'request timed out',
    };

    expect(await lookup()).toEqual(failure);
    expect(await lookup()).toEqual(failure);
    jest.setSystemTime(start + retryDelay - 1);
    expect(await lookup()).toEqual(failure);
    expect(get).toHaveBeenCalledTimes(1);
  });

  it.each([retryDelay, retryDelay + 1])(
    'retries an HTTP failure after %i milliseconds',
    async (elapsed) => {
      const lookup = createService();
      get.mockRejectedValueOnce(new Error('request timed out'));
      await lookup();
      respond();

      jest.setSystemTime(start + elapsed);

      expect(await lookup()).toEqual(network);
      expect(get).toHaveBeenCalledTimes(2);
    },
  );

  it.each([
    ['provider refused the lookup', 'provider refused the lookup'],
    [undefined, 'ipwho.is failed'],
  ])(
    'treats provider success=false as a retryable failure (%s)',
    async (message, expected) => {
      const lookup = createService();
      get.mockResolvedValueOnce({
        data: { success: false, message, ip: network.ip },
      });
      const failure = {
        ip: null,
        isp: null,
        country: null,
        city: null,
        error: expected,
      };

      expect(await lookup()).toEqual(failure);
      jest.setSystemTime(start + retryDelay - 1);
      expect(await lookup()).toEqual(failure);
      expect(get).toHaveBeenCalledTimes(1);

      respond();
      jest.setSystemTime(start + retryDelay);
      expect(await lookup()).toEqual(network);
      expect(get).toHaveBeenCalledTimes(2);
    },
  );

  it.each([undefined, null, {}, new Error('')])(
    'uses a fallback message for a rejection without an error message (%p)',
    async (reason) => {
      const lookup = createService();
      get.mockRejectedValueOnce(reason);

      expect(await lookup()).toEqual({
        ip: null,
        isp: null,
        country: null,
        city: null,
        error: 'public ip lookup failed',
      });
    },
  );

  it('switches from the short failure cache to the full success window on recovery', async () => {
    const lookup = createService();
    get.mockRejectedValueOnce(new Error('offline'));
    await lookup();
    respond();
    jest.setSystemTime(start + retryDelay);
    expect(await lookup()).toEqual(network);

    jest.setSystemTime(start + retryDelay + hour - 1);
    expect(await lookup()).toEqual(network);
    expect(get).toHaveBeenCalledTimes(2);

    respond('203.0.113.20');
    jest.setSystemTime(start + retryDelay + hour);
    expect(await lookup()).toEqual({ ...network, ip: '203.0.113.20' });
    expect(get).toHaveBeenCalledTimes(3);
  });

  it('replaces expired success data with the short failure cache if refresh fails', async () => {
    const lookup = createService();
    respond();
    await lookup();
    get.mockRejectedValueOnce(new Error('offline'));
    jest.setSystemTime(start + hour);
    const failure = await lookup();

    expect(failure).toEqual({
      ip: null,
      isp: null,
      country: null,
      city: null,
      error: 'offline',
    });
    jest.setSystemTime(start + hour + retryDelay - 1);
    expect(await lookup()).toEqual(failure);
    expect(get).toHaveBeenCalledTimes(2);

    respond('203.0.113.20');
    jest.setSystemTime(start + hour + retryDelay);
    expect(await lookup()).toEqual({ ...network, ip: '203.0.113.20' });
    expect(get).toHaveBeenCalledTimes(3);
  });

  it('starts a fresh five-minute retry window after each repeated failure', async () => {
    const lookup = createService();
    get.mockRejectedValueOnce(new Error('first failure'));
    await lookup();
    get.mockRejectedValueOnce(new Error('second failure'));
    jest.setSystemTime(start + retryDelay);
    expect((await lookup()).error).toBe('second failure');

    jest.setSystemTime(start + 2 * retryDelay - 1);
    expect((await lookup()).error).toBe('second failure');
    expect(get).toHaveBeenCalledTimes(2);

    respond();
    jest.setSystemTime(start + 2 * retryDelay);
    expect(await lookup()).toEqual(network);
    expect(get).toHaveBeenCalledTimes(3);
  });

  it('keeps cache data and failures local to each service instance', async () => {
    const firstLookup = createService();
    const secondLookup = createService();
    respond();
    get.mockRejectedValueOnce(new Error('second instance is offline'));

    expect(await firstLookup()).toEqual(network);
    expect((await secondLookup()).error).toBe('second instance is offline');
    expect(await firstLookup()).toEqual(network);
    expect((await secondLookup()).error).toBe('second instance is offline');
    expect(get).toHaveBeenCalledTimes(2);
  });
});
