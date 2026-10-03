import { OverviewStatsService } from './overview-stats.service';
import { PrismaService } from '../prisma/prisma.service';

describe('OverviewStatsService daily trend buckets', () => {
  // These aggregation tests do not connect to a database.
  const service = new OverviewStatsService({} as PrismaService);
  const days = (from: string, to: string, dates: string[] = []) =>
    service['days'](
      new Date(from),
      new Date(to),
      dates.map((d) => new Date(d)),
    );

  it('includes both UTC boundary days and counts timestamps by UTC date', () => {
    expect(
      days('2026-10-01T08:00:00Z', '2026-10-03T08:00:00Z', [
        '2026-10-01T08:00:00Z',
        '2026-10-02T23:59:59Z',
        '2026-10-03T00:00:00Z',
        '2026-10-03T08:00:00Z',
      ]),
    ).toEqual([
      { date: '2026-10-01', count: 1 },
      { date: '2026-10-02', count: 1 },
      { date: '2026-10-03', count: 2 },
    ]);
  });

  it('returns zero-filled days and ignores dates outside the buckets', () => {
    expect(
      days('2026-10-01T23:00:00Z', '2026-10-03T00:00:00Z', [
        '2026-09-30T23:59:59Z',
        '2026-10-04T00:00:00Z',
      ]),
    ).toEqual([
      { date: '2026-10-01', count: 0 },
      { date: '2026-10-02', count: 0 },
      { date: '2026-10-03', count: 0 },
    ]);
  });

  it('groups offset timestamps by UTC rather than their written local date', () => {
    expect(
      days('2026-10-01T00:00:00Z', '2026-10-01T23:59:59Z', [
        '2026-10-02T01:00:00+05:00',
        '2026-09-30T20:00:00-04:00',
      ]),
    ).toEqual([{ date: '2026-10-01', count: 2 }]);
  });

  it.each([
    ['2026-03-28', '2026-03-29', '2026-03-30'],
    ['2026-10-24', '2026-10-25', '2026-10-26'],
    ['2028-02-28', '2028-02-29', '2028-03-01'],
    ['2026-12-31', '2027-01-01', '2027-01-02'],
  ])('keeps consecutive days across calendar boundaries: %s', (...dates) => {
    expect(
      days(`${dates[0]}T12:00:00Z`, `${dates[2]}T12:00:00Z`, dates),
    ).toEqual(dates.map((date) => ({ date, count: 1 })));
  });

  it('returns no buckets for a reversed date range', () => {
    expect(days('2026-10-03T00:00:00Z', '2026-10-01T00:00:00Z')).toEqual([]);
  });
});
