jest.mock('cron', () => ({
  CronJob: jest.fn().mockImplementation(() => ({ start: jest.fn() })),
}));

import { Logger } from '@nestjs/common';
import type { SchedulerRegistry } from '@nestjs/schedule';
import type { PrismaService } from '../prisma/prisma.service';
import type { ImageCrawlerService } from './image-crawler.service';
import { ImageModerationService } from './image-moderation.service';
import type { ImageVerdict, SightengineService } from './sightengine.service';

type ScanData = {
  status?: string;
  totalImages?: number;
  scannedImages?: number;
  flaggedCount?: number;
  sexualCount?: number;
  violentCount?: number;
  religiousCount?: number;
  errorMessage?: string | null;
  finishedAt?: Date | null;
};
type ScanUpdate = { where: { id: string }; data: ScanData };

function verdict(categories: string[] = [], error?: string): ImageVerdict {
  return {
    sexualScore: categories.includes('sexual') ? 0.9 : 0,
    violentScore: categories.includes('violent') ? 0.8 : 0,
    religiousScore: categories.includes('religious') ? 0.7 : 0,
    categories,
    flagged: categories.length > 0,
    raw: null,
    ...(error ? { error } : {}),
  };
}

function createService(imageCount = 8) {
  const images = Array.from({ length: imageCount }, (_, index) => ({
    imageUrl: `https://example.test/image-${index}.jpg`,
    pageUrl: 'https://example.test/',
  }));
  const prisma = {
    imageScan: {
      create: jest.fn().mockResolvedValue({ id: 'scan-1' }),
      update: jest.fn<Promise<ScanData>, [ScanUpdate]>(),
    },
    imageResult: {
      create: jest.fn().mockResolvedValue({}),
    },
  };
  prisma.imageScan.update.mockImplementation(({ data }) =>
    Promise.resolve(data),
  );
  const crawler = {
    extractSiteImages: jest.fn().mockResolvedValue(images),
  };
  const sight = {
    checkImage: jest.fn<Promise<ImageVerdict>, [string]>(),
  };
  sight.checkImage.mockResolvedValue(verdict());
  const scheduler = { addCronJob: jest.fn() };
  const service = new ImageModerationService(
    prisma as unknown as PrismaService,
    crawler as unknown as ImageCrawlerService,
    sight as unknown as SightengineService,
    scheduler as unknown as SchedulerRegistry,
  );
  jest
    .spyOn(service as unknown as { sleep(ms: number): Promise<void> }, 'sleep')
    .mockResolvedValue(undefined);

  return { service, prisma, crawler, sight, images };
}

function expectCounters(
  data: ScanData | undefined,
  scanned: number,
  flagged: number,
  sexual: number,
  violent: number,
  religious: number,
) {
  expect(data).toMatchObject({
    scannedImages: scanned,
    flaggedCount: flagged,
    sexualCount: sexual,
    violentCount: violent,
    religiousCount: religious,
  });
}

describe('ImageModerationService persisted progress', () => {
  beforeEach(() => {
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('preserves a partial batch when the next image check fails', async () => {
    const { service, prisma, sight } = createService();
    sight.checkImage
      .mockResolvedValueOnce(verdict(['sexual', 'violent']))
      .mockResolvedValueOnce(verdict(['religious']))
      .mockRejectedValueOnce(new Error('Image check failed'));

    const result = await service.scanSite('website-1', 'https://example.test');

    expectCounters(result, 2, 2, 1, 1, 1);
    expect(result).toMatchObject({
      status: 'FAILED',
      errorMessage: 'Image check failed',
      finishedAt: expect.any(Date) as Date,
    });
    expect(prisma.imageResult.create).toHaveBeenCalledTimes(2);
    expect(prisma.imageScan.update).toHaveBeenLastCalledWith({
      where: { id: 'scan-1' },
      data: result,
    });
  });

  it('does not count an image whose result failed to persist', async () => {
    const { service, prisma, sight } = createService();
    sight.checkImage
      .mockResolvedValueOnce(verdict(['sexual']))
      .mockResolvedValueOnce(verdict(['violent', 'religious']));
    prisma.imageResult.create
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(new Error('Result write failed'));

    const result = await service.scanSite('website-1', 'https://example.test');

    expectCounters(result, 1, 1, 1, 0, 0);
    expect(result.errorMessage).toBe('Result write failed');
    expect(sight.checkImage).toHaveBeenCalledTimes(2);
  });

  it('keeps every counter at the five-image progress checkpoint', async () => {
    const { service, prisma, sight } = createService(5);
    sight.checkImage
      .mockResolvedValueOnce(verdict(['sexual', 'violent']))
      .mockResolvedValueOnce(verdict(['religious']))
      .mockResolvedValueOnce(verdict())
      .mockResolvedValueOnce(verdict(['violent']))
      .mockResolvedValueOnce(verdict(['sexual', 'religious']));

    await service.scanSite('website-1', 'https://example.test');

    expectCounters(
      prisma.imageScan.update.mock.calls[1]?.[0].data,
      5,
      4,
      2,
      2,
      2,
    );
    expect(prisma.imageScan.update.mock.calls[1]?.[0].data).not.toHaveProperty(
      'status',
    );
    expect(prisma.imageScan.update.mock.calls[1]?.[0].data).not.toHaveProperty(
      'finishedAt',
    );
    expect(prisma.imageScan.update).toHaveBeenCalledTimes(3);
  });

  it('preserves results persisted since the last checkpoint', async () => {
    const { service, prisma, sight } = createService();
    for (let index = 0; index < 7; index++) {
      sight.checkImage.mockResolvedValueOnce(
        verdict(index < 5 ? ['sexual'] : ['violent', 'religious']),
      );
    }
    sight.checkImage.mockRejectedValueOnce(new Error('Eighth check failed'));

    const result = await service.scanSite('website-1', 'https://example.test');

    expectCounters(result, 7, 7, 5, 2, 2);
    expect(prisma.imageResult.create).toHaveBeenCalledTimes(7);
    expect(prisma.imageScan.update).toHaveBeenCalledTimes(3);
  });

  it('recovers all persisted counters when a progress update fails', async () => {
    const { service, prisma, sight } = createService();
    sight.checkImage.mockResolvedValue(verdict(['religious']));
    prisma.imageScan.update
      .mockResolvedValueOnce({ totalImages: 8 })
      .mockRejectedValueOnce(new Error('Checkpoint write failed'));

    const result = await service.scanSite('website-1', 'https://example.test');

    expectCounters(result, 5, 5, 0, 0, 5);
    expect(result.status).toBe('FAILED');
    expect(result.errorMessage).toBe('Checkpoint write failed');
    expect(prisma.imageResult.create).toHaveBeenCalledTimes(5);
  });

  it.each(['crawl', 'total update', 'first check', 'first result'])(
    'records zero progress when %s fails before any result is stored',
    async (step) => {
      const { service, prisma, crawler, sight } = createService();
      const failure = new Error(`${step} failed`);
      if (step === 'crawl')
        crawler.extractSiteImages.mockRejectedValue(failure);
      if (step === 'total update')
        prisma.imageScan.update.mockRejectedValueOnce(failure);
      if (step === 'first check') sight.checkImage.mockRejectedValue(failure);
      if (step === 'first result')
        prisma.imageResult.create.mockRejectedValue(failure);

      const result = await service.scanSite(
        'website-1',
        'https://example.test',
      );

      expectCounters(result, 0, 0, 0, 0, 0);
      expect(result.status).toBe('FAILED');
      expect(result.errorMessage).toBe(failure.message);
    },
  );

  it('uses the existing fallback message for non-Error failures', async () => {
    const { service, sight } = createService();
    sight.checkImage
      .mockResolvedValueOnce(verdict(['violent']))
      .mockRejectedValueOnce('untyped failure');

    const result = await service.scanSite('website-1', 'https://example.test');

    expectCounters(result, 1, 1, 0, 1, 0);
    expect(result.errorMessage).toBe('Unknown error');
  });

  it('preserves final totals and counts a multi-category image only once as flagged', async () => {
    const { service, prisma, sight } = createService(3);
    sight.checkImage
      .mockResolvedValueOnce(verdict(['sexual', 'violent', 'religious']))
      .mockResolvedValueOnce(verdict())
      .mockResolvedValueOnce(verdict(['violent']));

    const result = await service.scanSite('website-1', 'https://example.test');

    expectCounters(result, 3, 2, 1, 2, 1);
    expect(result.status).toBe('COMPLETED');
    expect(result.finishedAt).toBeInstanceOf(Date);
    expect(prisma.imageScan.update).toHaveBeenNthCalledWith(1, {
      where: { id: 'scan-1' },
      data: { totalImages: 3 },
    });
    expect(prisma.imageResult.create).toHaveBeenCalledTimes(3);
  });

  it('still stores and counts an unflagged provider-error verdict as processed', async () => {
    const { service, prisma, sight } = createService(2);
    sight.checkImage
      .mockResolvedValueOnce(verdict([], 'Provider unavailable'))
      .mockRejectedValueOnce(new Error('Later failure'));

    const result = await service.scanSite('website-1', 'https://example.test');

    expectCounters(result, 1, 0, 0, 0, 0);
    expect(prisma.imageResult.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        scanId: 'scan-1',
        imageUrl: 'https://example.test/image-0.jpg',
        pageUrl: 'https://example.test/',
        errorMessage: 'Provider unavailable',
        flagged: false,
      }) as object,
    });
  });

  it('completes empty crawls without checking images or inventing results', async () => {
    const { service, prisma, sight } = createService(0);

    const result = await service.scanSite('website-1', 'https://example.test');

    expect(result).toEqual({
      status: 'COMPLETED',
      totalImages: 0,
      finishedAt: expect.any(Date) as Date,
    });
    expect(sight.checkImage).not.toHaveBeenCalled();
    expect(prisma.imageResult.create).not.toHaveBeenCalled();
    expect(prisma.imageScan.update).toHaveBeenCalledTimes(1);
  });

  it('does not leak completed counters into a later failed scan', async () => {
    const { service, prisma, crawler, sight } = createService(1);
    sight.checkImage.mockResolvedValue(verdict(['sexual', 'violent']));
    await service.scanSite('website-1', 'https://example.test');
    prisma.imageScan.create.mockResolvedValueOnce({ id: 'scan-2' });
    crawler.extractSiteImages.mockRejectedValueOnce(new Error('Second crawl'));

    const result = await service.scanSite('website-2', 'https://second.test');

    expectCounters(result, 0, 0, 0, 0, 0);
    expect(prisma.imageScan.update).toHaveBeenLastCalledWith({
      where: { id: 'scan-2' },
      data: result,
    });
  });

  it('propagates failure-summary persistence errors', async () => {
    const { service, prisma, crawler } = createService();
    crawler.extractSiteImages.mockRejectedValue(new Error('Crawl failed'));
    const failure = new Error('Failure summary write failed');
    prisma.imageScan.update.mockRejectedValue(failure);

    await expect(
      service.scanSite('website-1', 'https://example.test'),
    ).rejects.toBe(failure);
    expect(prisma.imageScan.update).toHaveBeenCalledTimes(1);
  });

  it('does not attempt progress updates when scan creation fails', async () => {
    const { service, prisma, crawler } = createService();
    const failure = new Error('Scan creation failed');
    prisma.imageScan.create.mockRejectedValue(failure);

    await expect(
      service.scanSite('website-1', 'https://example.test'),
    ).rejects.toBe(failure);
    expect(crawler.extractSiteImages).not.toHaveBeenCalled();
    expect(prisma.imageScan.update).not.toHaveBeenCalled();
  });
});
