import { readFileSync } from 'node:fs';
import type { PrismaService } from '../prisma/prisma.service';
import { SystemStatusService } from './system-status.service';

jest.mock('node:fs', () => ({
  ...jest.requireActual<typeof import('node:fs')>('node:fs'),
  readFileSync: jest.fn(),
  statfsSync: jest.fn(),
}));

const START = new Date('2026-10-12T08:00:00.000Z').getTime();
const readCounters = jest.mocked(readFileSync);

function interfaceLine(name: string, rxBytes: number, txBytes: number): string {
  return ` ${name}: ${[rxBytes, 0, 0, 0, 0, 0, 0, 0, txBytes, 0, 0, 0, 0, 0, 0, 0].join(' ')}`;
}

function counters(rxBytes: number, txBytes: number): string {
  return [
    'Inter-| Receive | Transmit',
    ' face | bytes | bytes',
    interfaceLine('eth0', rxBytes, txBytes),
  ].join('\n');
}

describe('SystemStatusService network sampling', () => {
  let service: SystemStatusService;

  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(START);
    readCounters.mockReset();
    // This suite exercises the counter reader/sampler without calling the
    // database, public-IP provider, or any other host-resource probe.
    service = new SystemStatusService({} as PrismaService);
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  function sample(atSeconds: number, rxBytes: number, txBytes: number) {
    jest.setSystemTime(START + atSeconds * 1000);
    readCounters.mockReturnValueOnce(counters(rxBytes, txBytes));
    return service['getNetworkUsage']();
  }

  function fail(
    atSeconds: number,
    error: unknown = new Error('counter read failed'),
  ) {
    jest.setSystemTime(START + atSeconds * 1000);
    readCounters.mockImplementationOnce(() => {
      throw error;
    });
    return service['getNetworkUsage']();
  }

  it('reports cumulative counters but zero rates for the first successful sample', () => {
    expect(sample(0, 1_000_000, 2_000_000)).toEqual({
      rxBytes: 1_000_000,
      txBytes: 2_000_000,
      rxBytesPerSec: 0,
      txBytesPerSec: 0,
      interfaceCount: 1,
      sampledAt: new Date(START).toISOString(),
      error: null,
    });
    expect(readCounters).toHaveBeenCalledWith('/proc/net/dev', 'utf8');
  });

  it('calculates independent receive/transmit deltas across successful samples', () => {
    sample(0, 1_000_000, 2_000_000);

    expect(sample(2, 1_001_201, 2_000_400)).toMatchObject({
      rxBytesPerSec: 601,
      txBytesPerSec: 200,
      error: null,
    });
  });

  it('preserves the last successful counters and timestamp across a read failure', () => {
    sample(0, 1_000_000, 2_000_000);
    fail(1);

    expect(sample(4, 1_001_200, 2_000_400)).toMatchObject({
      rxBytes: 1_001_200,
      txBytes: 2_000_400,
      rxBytesPerSec: 300,
      txBytesPerSec: 100,
      sampledAt: new Date(START + 4000).toISOString(),
      error: null,
    });
  });

  it('spans consecutive read failures using the full successful-sample interval', () => {
    sample(0, 5_000_000, 8_000_000);
    fail(1);
    fail(2);
    fail(7);

    expect(sample(10, 5_002_000, 8_007_000)).toMatchObject({
      rxBytesPerSec: 200,
      txBytesPerSec: 700,
    });
  });

  it('does not treat initial failures as a successful zero-byte baseline', () => {
    fail(0);
    fail(1);

    expect(sample(5, 100_000_000, 200_000_000)).toMatchObject({
      rxBytesPerSec: 0,
      txBytesPerSec: 0,
      error: null,
    });
    expect(sample(7, 100_000_300, 200_000_600)).toMatchObject({
      rxBytesPerSec: 150,
      txBytesPerSec: 300,
    });
  });

  it('reports zero traffic after recovery if the counters did not change', () => {
    sample(0, 1_000_000, 2_000_000);
    fail(1);

    expect(sample(3, 1_000_000, 2_000_000)).toMatchObject({
      rxBytesPerSec: 0,
      txBytesPerSec: 0,
    });
  });

  it('advances the baseline after recovery for the next sampling window', () => {
    sample(0, 1_000_000, 2_000_000);
    fail(1);
    sample(4, 1_001_200, 2_000_400);

    expect(sample(6, 1_001_300, 2_001_400)).toMatchObject({
      rxBytesPerSec: 50,
      txBytesPerSec: 500,
    });
    fail(7);
    expect(sample(10, 1_001_700, 2_002_200)).toMatchObject({
      rxBytesPerSec: 100,
      txBytesPerSec: 200,
    });
  });

  it('retains the existing unavailable-sample response shape and current timestamp', () => {
    sample(0, 1_000_000, 2_000_000);

    expect(fail(2)).toEqual({
      rxBytes: 0,
      txBytes: 0,
      rxBytesPerSec: 0,
      txBytesPerSec: 0,
      interfaceCount: 0,
      sampledAt: new Date(START + 2000).toISOString(),
      error: 'counter read failed',
    });
  });

  it('uses the existing fallback message for failures without an Error message', () => {
    expect(fail(0, 'unavailable')).toMatchObject({
      rxBytesPerSec: 0,
      txBytesPerSec: 0,
      error: 'network usage unavailable',
    });
    expect(sample(2, 10_000, 20_000)).toMatchObject({
      rxBytesPerSec: 0,
      txBytesPerSec: 0,
    });
  });

  it('keeps decreasing counters nonnegative and adopts the new counter baseline', () => {
    sample(0, 1_000_000, 2_000_000);
    fail(1);

    expect(sample(4, 100, 200)).toMatchObject({
      rxBytesPerSec: 0,
      txBytesPerSec: 0,
    });
    expect(sample(6, 300, 800)).toMatchObject({
      rxBytesPerSec: 100,
      txBytesPerSec: 300,
    });
  });

  it('accepts successful zero-byte samples as valid baselines', () => {
    sample(0, 1_000_000, 2_000_000);
    sample(2, 0, 0);

    expect(sample(4, 1000, 2000)).toMatchObject({
      rxBytesPerSec: 500,
      txBytesPerSec: 1000,
    });
  });

  it('keeps rates finite when successful samples share the same timestamp', () => {
    sample(0, 1000, 2000);

    expect(sample(0, 1200, 2600)).toMatchObject({
      rxBytesPerSec: 0,
      txBytesPerSec: 0,
    });
    expect(sample(2, 1400, 2800)).toMatchObject({
      rxBytesPerSec: 100,
      txBytesPerSec: 100,
    });
  });

  it('sums non-loopback interfaces and ignores malformed counter lines', () => {
    readCounters.mockReturnValueOnce(
      [
        'Inter-| Receive | Transmit',
        ' face | bytes | bytes',
        interfaceLine('lo', 999_999, 999_999),
        interfaceLine('eth0', 1000, 2000),
        interfaceLine('wlan0', 3000, 4000),
        'missing separator',
        'short: 1 2 3',
        interfaceLine('invalid0', Number.NaN, 9000),
      ].join('\n'),
    );

    expect(service['getNetworkUsage']()).toMatchObject({
      rxBytes: 4000,
      txBytes: 6000,
      interfaceCount: 2,
      error: null,
    });
  });

  it('keeps each service instance sampling baseline independent', () => {
    sample(0, 1_000_000, 2_000_000);
    const other = new SystemStatusService({} as PrismaService);
    readCounters.mockReturnValueOnce(counters(100, 200));

    expect(other['getNetworkUsage']()).toMatchObject({
      rxBytesPerSec: 0,
      txBytesPerSec: 0,
    });
    fail(1);
    expect(sample(4, 1_001_200, 2_000_400)).toMatchObject({
      rxBytesPerSec: 300,
      txBytesPerSec: 100,
    });
  });
});
