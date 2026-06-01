import { Injectable, Logger } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import { PrismaService } from '../prisma/prisma.service';
import { ImageCrawlerService } from './image-crawler.service';
import { SightengineService } from './sightengine.service';

const envNumber = (name: string, fallback: number, min: number) => {
  const value = Number(process.env[name]);
  return Number.isFinite(value) ? Math.max(min, value) : fallback;
};

const MAX_PAGES_PER_SITE = envNumber('IMAGE_MODERATION_MAX_PAGES', 300, 1);
const MAX_IMAGES_PER_SITE = envNumber('IMAGE_MODERATION_MAX_IMAGES', 5_000, 1);
const CRAWL_PAGE_DELAY_MS = envNumber('IMAGE_MODERATION_CRAWL_PAGE_DELAY_MS', 150, 0);
const DELAY_BETWEEN_SITES_MS = 4_000;     // sayt block qilmasin
const DELAY_BETWEEN_IMAGES_MS = 300;      // Sightengine rate limit (~10/s)

@Injectable()
export class ImageModerationService {
  private readonly logger = new Logger(ImageModerationService.name);
  private running = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly crawler: ImageCrawlerService,
    private readonly sight: SightengineService,
    private readonly scheduler: SchedulerRegistry,
  ) {
    this.startDailyJob();
  }

  // ── CRON: har kuni 03:00 da boshlanadi ────────────────────────────────────
  private startDailyJob() {
    const job = new CronJob('0 0 3 * * *', () => {
      this.logger.log('Daily image moderation scan started (03:00)');
      this.scanAll().catch(e =>
        this.logger.error('Daily image scan failed', e instanceof Error ? e.stack : e),
      );
    });
    this.scheduler.addCronJob('image-moderation-daily', job);
    job.start();
    this.logger.log('Image moderation daily cron registered: 03:00');
  }

  // ── 1 sayt 1 kunda 1 marta ────────────────────────────────────────────────
  /** Returns true if site already has a scan started today (any status). */
  private async scannedToday(websiteId: string): Promise<boolean> {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const exists = await this.prisma.imageScan.findFirst({
      where: { websiteId, startedAt: { gte: startOfDay } },
      select: { id: true },
    });
    return !!exists;
  }

  // ── SCAN ALL (sequential, polite delays) ──────────────────────────────────
  async scanAll(): Promise<{ scanned: number; skipped: number }> {
    if (this.running) {
      this.logger.warn('scanAll already running — skipping');
      return { scanned: 0, skipped: 0 };
    }
    this.running = true;
    let scanned = 0;
    let skipped = 0;
    try {
      const sites = await this.prisma.website.findMany({ orderBy: { createdAt: 'asc' } });
      for (const site of sites) {
        if (await this.scannedToday(site.id)) {
          skipped++;
          continue;
        }
        try {
          await this.scanSite(site.id, site.url);
          scanned++;
        } catch (e) {
          this.logger.error(`scanSite failed ${site.url}`, (e as Error).message);
        }
        await this.sleep(DELAY_BETWEEN_SITES_MS);
      }
    } finally {
      this.running = false;
    }
    this.logger.log(`Daily image scan finished: ${scanned} scanned, ${skipped} skipped`);
    return { scanned, skipped };
  }

  // ── SCAN ONE SITE ─────────────────────────────────────────────────────────
  async scanSite(websiteId: string, url: string) {
    const scan = await this.prisma.imageScan.create({
      data: { websiteId, status: 'RUNNING' },
    });

    try {
      const images = await this.crawler.extractSiteImages(url, {
        maxPages: MAX_PAGES_PER_SITE,
        maxImages: MAX_IMAGES_PER_SITE,
        pageDelayMs: CRAWL_PAGE_DELAY_MS,
      });

      if (images.length === 0) {
        return this.prisma.imageScan.update({
          where: { id: scan.id },
          data: {
            status: 'COMPLETED',
            totalImages: 0,
            finishedAt: new Date(),
          },
        });
      }

      await this.prisma.imageScan.update({
        where: { id: scan.id },
        data: { totalImages: images.length },
      });

      let sexual = 0, violent = 0, religious = 0, flagged = 0, processed = 0;

      for (const image of images) {
        const verdict = await this.sight.checkImage(image.imageUrl);

        await this.prisma.imageResult.create({
          data: {
            scanId: scan.id,
            imageUrl: image.imageUrl,
            pageUrl: image.pageUrl,
            sexualScore: verdict.sexualScore,
            violentScore: verdict.violentScore,
            religiousScore: verdict.religiousScore,
            categories: verdict.categories,
            rawSignals: (verdict.raw ?? {}) as unknown as object,
            flagged: verdict.flagged,
            errorMessage: verdict.error || null,
          },
        });

        if (verdict.flagged) flagged++;
        if (verdict.categories.includes('sexual')) sexual++;
        if (verdict.categories.includes('violent')) violent++;
        if (verdict.categories.includes('religious')) religious++;
        processed++;

        if (processed % 5 === 0) {
          await this.prisma.imageScan.update({
            where: { id: scan.id },
            data: { scannedImages: processed, flaggedCount: flagged },
          });
        }

        await this.sleep(DELAY_BETWEEN_IMAGES_MS);
      }

      return this.prisma.imageScan.update({
        where: { id: scan.id },
        data: {
          status: 'COMPLETED',
          scannedImages: processed,
          flaggedCount: flagged,
          sexualCount: sexual,
          violentCount: violent,
          religiousCount: religious,
          finishedAt: new Date(),
        },
      });
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Unknown error';
      return this.prisma.imageScan.update({
        where: { id: scan.id },
        data: { status: 'FAILED', errorMessage: message, finishedAt: new Date() },
      });
    }
  }

  // ── QUERIES (controller uchun) ────────────────────────────────────────────

  /** Latest scan summary per website + counts. */
  async getOverview() {
    const sites = await this.prisma.website.findMany({
      orderBy: { createdAt: 'asc' },
      select: { id: true, url: true, label: true },
    });

    const latest = await Promise.all(
      sites.map(async site => {
        const scan = await this.prisma.imageScan.findFirst({
          where: { websiteId: site.id },
          orderBy: { startedAt: 'desc' },
        });
        return { ...site, latestScan: scan };
      }),
    );

    return latest;
  }

  /** All scans for a website (history). */
  getSiteScans(websiteId: string) {
    return this.prisma.imageScan.findMany({
      where: { websiteId },
      orderBy: { startedAt: 'desc' },
    });
  }

  /** Detail: scan + all flagged image results. */
  async getScanDetail(scanId: string) {
    const scan = await this.prisma.imageScan.findUnique({
      where: { id: scanId },
      include: { website: true },
    });
    if (!scan) return null;

    const results = await this.prisma.imageResult.findMany({
      where: { scanId },
      orderBy: [{ flagged: 'desc' }, { sexualScore: 'desc' }],
    });
    return { scan, results };
  }

  isRunning() {
    return {
      running: this.running,
      configured: this.sight.isConfigured(),
      maxPages: MAX_PAGES_PER_SITE,
      maxImages: MAX_IMAGES_PER_SITE,
      crawlPageDelayMs: CRAWL_PAGE_DELAY_MS,
    };
  }

  private sleep(ms: number) {
    return new Promise(r => setTimeout(r, ms));
  }
}
