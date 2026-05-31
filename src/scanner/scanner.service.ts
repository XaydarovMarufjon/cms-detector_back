// src/scanner/scanner.service.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import axios from 'axios';
import { PrismaService } from '../prisma/prisma.service';
import { CmsDetectorService, type CmsDetectOptions, type CmsDetectionResult } from './cms-detector.service';
import { WhoisService } from './whois.service';
import { SiteInfoService } from './site-info.service';
import { AlertsService } from '../alerts/alerts.service';
import pLimit from 'p-limit';

export type BulkScanMode = 'FAST' | 'FULL';
type BulkScanJobStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'CANCELLED' | 'FAILED';

export interface BulkScanStartOptions {
  mode?: BulkScanMode;
  concurrency?: number;
  timeoutMs?: number;
  includeRecentlyScanned?: boolean;
  skipRecentHours?: number;
}

interface BulkScanRuntime {
  id: string;
  cancelled: boolean;
}

interface NormalizedBulkScanOptions {
  mode: BulkScanMode;
  concurrency: number;
  timeoutMs: number;
  includeRecentlyScanned: boolean;
  skipRecentHours: number;
}

interface DefacementFingerprint {
  title: string | null;
  titleHash: string | null;
  contentHash: string;
  structuralHash: string | null;
  textLength: number;
  assetCount: number;
  formCount: number;
  scriptCount: number;
  keywordHits: string[];
}

@Injectable()
export class ScannerService implements OnModuleInit {
  private readonly logger = new Logger(ScannerService.name);
  private readonly AUTO_SCAN_KEY = 'cms-auto-scan';
  private readonly AUTO_SCAN_CONCURRENCY = Math.min(50, Math.max(1, Number(process.env['AUTO_SCAN_CONCURRENCY'] || 16)));
  private readonly AUTO_SCAN_TIMEOUT_MS = Math.min(15_000, Math.max(2_000, Number(process.env['AUTO_SCAN_TIMEOUT_MS'] || 5_000)));
  private currentInterval = 360; // daqiqa (default: 6 soat)
  private autoScanRunning = false;
  private activeBulkJob: BulkScanRuntime | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly detector: CmsDetectorService,
    private readonly scheduler: SchedulerRegistry,
    private readonly whois: WhoisService,
    private readonly siteInfo: SiteInfoService,
    private readonly alerts: AlertsService,
  ) {
    this.startDefaultJob();
    this.startExpiryCheckJob();
  }

  onModuleInit() {
    this.resumeInterruptedBulkJob().catch(e => this.logger.error('Bulk scan resume failed', e));
  }

  // ── DEFAULT CRON ─────────────────────────────────────────────────────────
  private startDefaultJob() {
    const job = new CronJob(this.toAutoScanCronExpr(this.currentInterval), () => {
      this.logger.log(`Auto scan started (every ${this.currentInterval} min)`);
      this.runAutoScanWindow().catch(e => this.logger.error('Auto scan failed', e));
    });
    this.scheduler.addCronJob('auto-scan', job);
    job.start();
    this.logger.log(`✅ Auto scan started: every ${this.currentInterval} minutes`);
  }

  // ── INTERVAL SOZLASH (dashboard dan) ──────────────────────────────────────
  setInterval(minutes: number) {
    this.currentInterval = this.normalizeAutoScanInterval(minutes);

    try {
      const job = this.scheduler.getCronJob('auto-scan');
      job.stop();
      this.scheduler.deleteCronJob('auto-scan');
    } catch { }

    const cronExpr = this.toAutoScanCronExpr(this.currentInterval);

    const newJob = new CronJob(cronExpr, () => {
      this.logger.log(`Auto scan (every ${this.currentInterval} min)`);
      this.runAutoScanWindow().catch(e => this.logger.error('Auto scan failed', e));
    });

    this.scheduler.addCronJob('auto-scan', newJob);
    newJob.start();
    this.upsertAutoScanState({ intervalMinutes: this.currentInterval }).catch(() => {});
    const dangerous = this.currentInterval < 360;
    this.logger.log(`✅ Interval yangilandi: ${this.currentInterval} daqiqa${dangerous ? ' (dangerous)' : ''}`);
    return {
      interval: this.currentInterval,
      cronExpr,
      dangerous,
      message: `Har ${this.currentInterval} daqiqada skanerlash`,
    };
  }

  getInterval() {
    return { interval: this.currentInterval, dangerous: this.currentInterval < 360 };
  }

  // ── EXPIRY CHECK CRON (har kuni soat 02:00) ──────────────────────────────
  private startExpiryCheckJob() {
    const job = new CronJob('0 0 2 * * *', () => {
      this.logger.log('Expiry check started (daily 02:00)');
      this.checkExpiryAll().catch(e => this.logger.error('Expiry check failed', e));
    });
    this.scheduler.addCronJob('expiry-check', job);
    job.start();
    this.logger.log('✅ Expiry check job started: every day at 02:00');
  }

  async checkExpiryAll() {
    const sites = await this.prisma.website.findMany();
    const limit = pLimit(3); // sekin — tashqi API rate limit uchun

    await Promise.all(
      sites.map(site =>
        limit(async () => {
          try {
            // SSL + GEO + Headers (cache dan foydalanadi)
            await this.siteInfo.analyze(site.url, site.id);
          } catch { /* silent */ }

          // WHOIS faqat .uz domenlar uchun
          const host = site.url
            .replace(/^https?:\/\//, '')
            .split('/')[0]
            .replace(/^www\./, '');
          if (host.endsWith('.uz')) {
            try {
              await this.whois.lookup(site.url, site.id);
            } catch { /* silent */ }
          }

          // Har so'rov orasida 1.5 sekund kutish (ip-api.com: 45 req/min)
          await new Promise(r => setTimeout(r, 1500));
        })
      )
    );

    this.logger.log(`Expiry check done: ${sites.length} sites checked`);
  }

  private async runAutoScanWindow() {
    if (this.autoScanRunning) {
      this.logger.warn('Auto scan already running, skipping this tick');
      return;
    }

    this.autoScanRunning = true;
    const startedAt = new Date();
    const intervalMs = this.currentInterval * 60_000;
    const reserveMs = Math.min(60_000, Math.max(5_000, Math.floor(intervalMs * 0.05)));
    const deadline = Date.now() + Math.max(30_000, intervalMs - reserveMs);
    let scanned = 0;

    try {
      const state = await this.upsertAutoScanState({
        intervalMinutes: this.currentInterval,
        lastStartedAt: startedAt,
        lastFinishedAt: null,
        lastStatus: 'RUNNING',
        lastError: null,
        scannedInLastWindow: 0,
      });

      const sites = await this.prisma.website.findMany({
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        select: { id: true, url: true },
      });

      if (!sites.length) {
        await this.upsertAutoScanState({
          cursorWebsiteId: null,
          lastFinishedAt: new Date(),
          lastStatus: 'EMPTY',
          totalAtLastWindow: 0,
        });
        return;
      }

      const startIndex = state?.cursorWebsiteId
        ? Math.max(0, sites.findIndex(site => site.id === state.cursorWebsiteId))
        : 0;

      let nextIndex = startIndex === -1 ? 0 : startIndex;
      const maxExpectedBatchMs = (this.AUTO_SCAN_TIMEOUT_MS * 2) + 1_500;

      while (nextIndex < sites.length) {
        if (Date.now() + maxExpectedBatchMs > deadline) break;

        const batch = sites.slice(nextIndex, nextIndex + this.AUTO_SCAN_CONCURRENCY);
        await Promise.all(batch.map(site => this.scanAutoSite(site.id, site.url)));

        nextIndex += batch.length;
        scanned += batch.length;

        await this.upsertAutoScanState({
          cursorWebsiteId: sites[nextIndex]?.id ?? null,
          intervalMinutes: this.currentInterval,
          scannedInLastWindow: scanned,
          totalAtLastWindow: sites.length,
          lastStatus: nextIndex >= sites.length ? 'COMPLETED' : 'RUNNING',
        });
      }

      const completed = nextIndex >= sites.length;
      await this.upsertAutoScanState({
        cursorWebsiteId: completed ? null : sites[nextIndex]?.id ?? null,
        intervalMinutes: this.currentInterval,
        lastFinishedAt: new Date(),
        lastStatus: completed ? 'COMPLETED' : 'PAUSED_TIME_BUDGET',
        lastError: null,
        scannedInLastWindow: scanned,
        totalAtLastWindow: sites.length,
      });

      this.logger.log(
        `Auto scan ${completed ? 'completed' : 'paused'}: ${scanned}/${sites.length} sites, next=${completed ? 'start' : sites[nextIndex]?.url}`,
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await this.upsertAutoScanState({
        lastFinishedAt: new Date(),
        lastStatus: 'FAILED',
        lastError: message,
        scannedInLastWindow: scanned,
      }).catch(() => {});
      throw err;
    } finally {
      this.autoScanRunning = false;
    }
  }

  private async scanAutoSite(websiteId: string, url: string) {
    try {
      await this.scanOne(websiteId, url, { mode: 'FAST', timeoutMs: this.AUTO_SCAN_TIMEOUT_MS });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Auto scan item failed: ${url} ${message}`);
    }
  }

  private async upsertAutoScanState(data: Record<string, any>) {
    return this.prisma.autoScanState.upsert({
      where: { key: this.AUTO_SCAN_KEY },
      create: {
        key: this.AUTO_SCAN_KEY,
        intervalMinutes: this.currentInterval,
        ...data,
      },
      update: data,
    });
  }

  private normalizeAutoScanInterval(minutes: number): number {
    const value = Math.round(Number(minutes));
    if (!Number.isFinite(value)) return 360;
    return Math.max(15, value);
  }

  private toAutoScanCronExpr(minutes: number): string {
    if (minutes < 60) return `0 */${minutes} * * * *`;
    if (minutes === 60) return '0 0 * * * *';
    if (minutes < 1440 && minutes % 60 === 0) return `0 0 */${minutes / 60} * * *`;
    return '0 0 0 * * *';
  }

  // ── SCAN ALL ──────────────────────────────────────────────────────────────


  async scanAll() {
    const sites = await this.prisma.website.findMany();
    // Lower concurrency: at 10+ parallel, ~30 simultaneous fetches saturate the
    // local resolver / TCP stack and many sites flap to "unreachable".
    const limit = pLimit(4);

    const firstPass = await Promise.all(
      sites.map(site =>
        limit(async () => {
          const r = await this.scanOne(site.id, site.url);
          await new Promise(res => setTimeout(res, 200));
          return { site, result: r };
        })
      )
    );

    // Second pass — sequential retry for sites with no httpStatus and no CMS
    // (likely concurrency-induced transient fetch failures, not real blocks).
    const failed = firstPass.filter(p => p.result?.httpStatus == null && !p.result?.cms);
    for (const { site } of failed) {
      try {
        await this.scanOne(site.id, site.url);
        await new Promise(res => setTimeout(res, 400));
      } catch { /* ignore */ }
    }

    return firstPass.map(p => p.result);
  }

  // ── BULK SCAN JOBS ────────────────────────────────────────────────────────
  async startBulkScan(options: BulkScanStartOptions = {}) {
    const active = await this.findActiveBulkJob();
    if (active) {
      if (!this.activeBulkJob) {
        this.activeBulkJob = { id: active.id, cancelled: false };
        this.runBulkScanJob(active.id).catch(e => this.failBulkScanJob(active.id, e));
      }
      return this.getBulkScanJob(active.id);
    }

    const normalized = this.normalizeBulkScanOptions(options);
    const sites = await this.prisma.website.findMany({
      orderBy: { createdAt: 'asc' },
      select: { id: true, url: true },
    });

    const job = await this.prisma.bulkScanJob.create({
      data: {
        status: sites.length ? 'PENDING' : 'COMPLETED',
        mode: normalized.mode,
        concurrency: normalized.concurrency,
        timeoutMs: normalized.timeoutMs,
        includeRecentlyScanned: normalized.includeRecentlyScanned,
        skipRecentHours: normalized.skipRecentHours,
        total: sites.length,
        pending: sites.length,
        finishedAt: sites.length ? null : new Date(),
      },
    });

    if (sites.length) {
      await this.prisma.bulkScanJobItem.createMany({
        data: sites.map(site => ({
          jobId: job.id,
          websiteId: site.id,
          url: site.url,
        })),
      });
      this.activeBulkJob = { id: job.id, cancelled: false };
      this.runBulkScanJob(job.id).catch(e => this.failBulkScanJob(job.id, e));
    }

    return this.getBulkScanJob(job.id);
  }

  async getCurrentBulkScanJob() {
    const active = this.activeBulkJob
      ? await this.prisma.bulkScanJob.findUnique({ where: { id: this.activeBulkJob.id } })
      : null;
    if (active) return this.getBulkScanJob(active.id);

    const running = await this.findActiveBulkJob();
    if (running) return this.getBulkScanJob(running.id);

    const latest = await this.prisma.bulkScanJob.findFirst({ orderBy: { createdAt: 'desc' } });
    return latest ? this.getBulkScanJob(latest.id) : null;
  }

  async getBulkScanJob(id: string) {
    const job = await this.prisma.bulkScanJob.findUnique({ where: { id } });
    if (!job) return null;

    const items = await this.prisma.bulkScanJobItem.findMany({
      where: { jobId: id },
      orderBy: { updatedAt: 'desc' },
      take: 10,
      include: { website: { select: { url: true, label: true } } },
    });

    const done = job.completed + job.failed + job.skipped;
    const progressPercent = job.total > 0 ? Math.round((done / job.total) * 100) : 100;
    return {
      ...job,
      progressPercent,
      items,
    };
  }

  async cancelBulkScan(id: string) {
    if (this.activeBulkJob?.id === id) {
      this.activeBulkJob.cancelled = true;
    }

    await this.prisma.bulkScanJobItem.updateMany({
      where: { jobId: id, status: 'PENDING' },
      data: { status: 'SKIPPED', errorMessage: 'Bekor qilingan', finishedAt: new Date() },
    });
    await this.syncBulkCounters(id, { errorMessage: 'Bekor qilinmoqda...' });

    if (this.activeBulkJob?.id !== id) {
      await this.syncBulkCounters(id, {
        status: 'CANCELLED',
        finishedAt: new Date(),
        errorMessage: 'Bekor qilingan',
      });
    }

    return this.getBulkScanJob(id);
  }

  private async runBulkScanJob(jobId: string) {
    const runtime = this.activeBulkJob?.id === jobId
      ? this.activeBulkJob
      : (this.activeBulkJob = { id: jobId, cancelled: false });

    await this.prisma.bulkScanJobItem.updateMany({
      where: { jobId, status: 'RUNNING' },
      data: { status: 'PENDING', startedAt: null, errorMessage: null },
    });

    let job = await this.syncBulkCounters(jobId, {
      status: 'RUNNING',
      startedAt: new Date(),
      finishedAt: null,
      errorMessage: null,
    });
    if (!job) return;

    const config = this.normalizeBulkScanOptions({
      mode: job.mode as BulkScanMode,
      concurrency: job.concurrency,
      timeoutMs: job.timeoutMs,
      includeRecentlyScanned: job.includeRecentlyScanned,
      skipRecentHours: job.skipRecentHours,
    });

    const items = await this.prisma.bulkScanJobItem.findMany({
      where: { jobId, status: 'PENDING' },
      orderBy: { createdAt: 'asc' },
      include: {
        website: {
          include: {
            scans: {
              orderBy: { scannedAt: 'desc' },
              take: 1,
              select: { scannedAt: true },
            },
          },
        },
      },
    });

    const limit = pLimit(config.concurrency);
    await Promise.all(items.map(item => limit(() => this.processBulkScanItem(jobId, item, config, runtime))));

    job = await this.syncBulkCounters(jobId);
    if (!job) return;

    const status: BulkScanJobStatus = runtime.cancelled ? 'CANCELLED' : 'COMPLETED';
    await this.prisma.bulkScanJob.update({
      where: { id: jobId },
      data: {
        status,
        finishedAt: new Date(),
        errorMessage: runtime.cancelled ? 'Bekor qilingan' : null,
      },
    });

    if (this.activeBulkJob?.id === jobId) {
      this.activeBulkJob = null;
    }
    this.logger.log(`Bulk scan ${status.toLowerCase()}: ${jobId}`);
  }

  private async processBulkScanItem(
    jobId: string,
    item: any,
    config: NormalizedBulkScanOptions,
    runtime: BulkScanRuntime,
  ) {
    if (runtime.cancelled) {
      await this.skipBulkScanItem(jobId, item.id, 'Bekor qilingan');
      return;
    }

    const latestScanAt = item.website?.scans?.[0]?.scannedAt as Date | undefined;
    if (this.shouldSkipRecentlyScanned(latestScanAt, config)) {
      await this.skipBulkScanItem(jobId, item.id, `${config.skipRecentHours} soat ichida skanerlangan`);
      return;
    }

    const started = await this.markBulkScanItemRunning(jobId, item.id);
    if (!started) return;

    try {
      const saved = await this.scanOne(item.websiteId, item.url, {
        mode: config.mode,
        timeoutMs: config.timeoutMs,
      });

      await this.prisma.bulkScanJobItem.update({
        where: { id: item.id },
        data: {
          status: 'DONE',
          scanResultId: saved.id,
          errorMessage: saved.errorMessage,
          finishedAt: new Date(),
        },
      });
      await this.prisma.bulkScanJob.update({
        where: { id: jobId },
        data: { running: { decrement: 1 }, completed: { increment: 1 } },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await this.prisma.bulkScanJobItem.update({
        where: { id: item.id },
        data: { status: 'FAILED', errorMessage: message, finishedAt: new Date() },
      });
      await this.prisma.bulkScanJob.update({
        where: { id: jobId },
        data: { running: { decrement: 1 }, failed: { increment: 1 } },
      });
    }
  }

  private async markBulkScanItemRunning(jobId: string, itemId: string): Promise<boolean> {
    const updated = await this.prisma.bulkScanJobItem.updateMany({
      where: { id: itemId, status: 'PENDING' },
      data: { status: 'RUNNING', startedAt: new Date(), errorMessage: null },
    });
    if (updated.count === 0) return false;

    await this.prisma.bulkScanJob.update({
      where: { id: jobId },
      data: { pending: { decrement: 1 }, running: { increment: 1 } },
    });
    return true;
  }

  private async skipBulkScanItem(jobId: string, itemId: string, message: string) {
    const updated = await this.prisma.bulkScanJobItem.updateMany({
      where: { id: itemId, status: 'PENDING' },
      data: { status: 'SKIPPED', errorMessage: message, finishedAt: new Date() },
    });
    if (updated.count === 0) return;

    await this.prisma.bulkScanJob.update({
      where: { id: jobId },
      data: { pending: { decrement: 1 }, skipped: { increment: 1 } },
    });
  }

  private async findActiveBulkJob() {
    return this.prisma.bulkScanJob.findFirst({
      where: { status: { in: ['PENDING', 'RUNNING'] } },
      orderBy: { createdAt: 'desc' },
    });
  }

  private async resumeInterruptedBulkJob() {
    const job = await this.findActiveBulkJob();
    if (!job || this.activeBulkJob) return;
    this.activeBulkJob = { id: job.id, cancelled: false };
    this.logger.log(`Resuming bulk scan: ${job.id}`);
    this.runBulkScanJob(job.id).catch(e => this.failBulkScanJob(job.id, e));
  }

  private async failBulkScanJob(jobId: string, err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    this.logger.error(`Bulk scan failed: ${jobId} ${message}`);
    await this.syncBulkCounters(jobId, {
      status: 'FAILED',
      finishedAt: new Date(),
      errorMessage: message,
    }).catch(() => {});
    if (this.activeBulkJob?.id === jobId) this.activeBulkJob = null;
  }

  private async syncBulkCounters(jobId: string, extra: Record<string, any> = {}) {
    const [pending, running, completed, failed, skipped] = await Promise.all([
      this.prisma.bulkScanJobItem.count({ where: { jobId, status: 'PENDING' } }),
      this.prisma.bulkScanJobItem.count({ where: { jobId, status: 'RUNNING' } }),
      this.prisma.bulkScanJobItem.count({ where: { jobId, status: 'DONE' } }),
      this.prisma.bulkScanJobItem.count({ where: { jobId, status: 'FAILED' } }),
      this.prisma.bulkScanJobItem.count({ where: { jobId, status: 'SKIPPED' } }),
    ]);
    return this.prisma.bulkScanJob.update({
      where: { id: jobId },
      data: {
        pending,
        running,
        completed,
        failed,
        skipped,
        total: pending + running + completed + failed + skipped,
        ...extra,
      },
    });
  }

  private normalizeBulkScanOptions(options: BulkScanStartOptions): NormalizedBulkScanOptions {
    const mode: BulkScanMode = options.mode === 'FULL' ? 'FULL' : 'FAST';
    const defaultConcurrency = mode === 'FAST' ? 16 : 4;
    const maxConcurrency = mode === 'FAST' ? 50 : 10;
    const defaultTimeout = mode === 'FAST' ? 5_000 : 20_000;
    const minTimeout = mode === 'FAST' ? 2_000 : 5_000;
    const maxTimeout = mode === 'FAST' ? 15_000 : 30_000;

    const concurrencyRaw = Number(options.concurrency || defaultConcurrency);
    const timeoutRaw = Number(options.timeoutMs || defaultTimeout);
    const skipHoursRaw = Number(options.skipRecentHours || 6);

    return {
      mode,
      concurrency: Math.min(maxConcurrency, Math.max(1, Number.isFinite(concurrencyRaw) ? Math.round(concurrencyRaw) : defaultConcurrency)),
      timeoutMs: Math.min(maxTimeout, Math.max(minTimeout, Number.isFinite(timeoutRaw) ? Math.round(timeoutRaw) : defaultTimeout)),
      includeRecentlyScanned: !!options.includeRecentlyScanned,
      skipRecentHours: Math.min(168, Math.max(1, Number.isFinite(skipHoursRaw) ? Math.round(skipHoursRaw) : 6)),
    };
  }

  private shouldSkipRecentlyScanned(latestScanAt: Date | undefined, config: NormalizedBulkScanOptions): boolean {
    if (config.includeRecentlyScanned || !latestScanAt) return false;
    const ageMs = Date.now() - new Date(latestScanAt).getTime();
    return ageMs >= 0 && ageMs < config.skipRecentHours * 60 * 60 * 1000;
  }

  // ── SCAN ONE ──────────────────────────────────────────────────────────────
  async scanOne(websiteId: string, url: string, options: CmsDetectOptions = {}) {
    const host = this.extractHost(url);
    try {
      const result = await this.detector.detect(url, options);

      const fetchedNothing =
        result.httpStatus === null &&
        !result.cms &&
        !result.serverTech.length &&
        Object.keys(result.rawSignals || {}).length === 0;

      const saved = await this.prisma.scanResult.create({
        data: {
          websiteId,
          cms: result.cms,
          version: result.version,
          category: result.category,
          confidence: result.confidence,
          detectionMethods: result.detectionMethod,
          serverTech: result.serverTech,
          jsFrameworks: result.jsFrameworks,
          rawSignals: result.rawSignals,
          httpStatus: result.httpStatus,
          pageTitle: result.pageTitle,
          errorMessage: fetchedNothing ? 'Site unreachable (all fetches failed)' : null,
        },
      });

      // CMS change detection
      const prev = await this.prisma.scanResult.findFirst({
        where: { websiteId, id: { not: saved.id } },
        orderBy: { scannedAt: 'desc' },
      });
      if (prev?.cms && result.cms && prev.cms !== result.cms) {
        this.alerts.checkCmsChange(host, prev.cms, result.cms, websiteId).catch(() => {});
      }

      // Site down alert
      if (result.httpStatus !== null) {
        this.alerts.checkSiteDown(host, result.httpStatus, websiteId).catch(() => {});
      }

      await this.checkDefacement(host, websiteId, url, result).catch(e => {
        const message = e instanceof Error ? e.message : String(e);
        this.logger.warn(`Defacement check failed: ${url} ${message}`);
      });

      return saved;
    } catch (err) {
      let message = 'Unknown error';
      if (err instanceof Error) message = err.message;

      // Site is unreachable
      this.alerts.checkSiteDown(host, null, websiteId).catch(() => {});

      return this.prisma.scanResult.create({
        data: { websiteId, errorMessage: message },
      });
    }
  }

  private extractHost(url: string): string {
    try {
      const u = url.startsWith('http') ? url : `https://${url}`;
      return new URL(u).hostname;
    } catch { return url; }
  }

  private async checkDefacement(host: string, websiteId: string, url: string, result: CmsDetectionResult) {
    const current = this.readDefacementFingerprint(result);
    if (!current) return;

    const previous = await this.prisma.defacementSnapshot.findUnique({ where: { websiteId } });
    if (!previous) {
      await this.prisma.defacementSnapshot.create({
        data: {
          websiteId,
          domain: host,
          url,
          title: current.title,
          titleHash: current.titleHash,
          contentHash: current.contentHash,
          structuralHash: current.structuralHash,
          textLength: current.textLength,
          assetCount: current.assetCount,
          formCount: current.formCount,
          scriptCount: current.scriptCount,
          keywordHits: current.keywordHits,
          status: current.keywordHits.length ? 'SUSPECTED' : 'BASELINE',
          changeScore: current.keywordHits.length ? 90 : 0,
          changeReasons: current.keywordHits.length
            ? [`Defacement keyword: ${current.keywordHits.slice(0, 3).join(', ')}`]
            : [],
          lastChangedAt: current.keywordHits.length ? new Date() : null,
          lastCheckedAt: new Date(),
        },
      });
      if (current.keywordHits.length) {
        await this.alerts.checkDefacementChange(
          host,
          90,
          [`Defacement keyword: ${current.keywordHits.slice(0, 3).join(', ')}`],
          websiteId,
        );
      }
      return;
    }

    const assessment = this.assessDefacement(previous, current, result.httpStatus);
    const changed = assessment.status === 'CHANGED' || assessment.status === 'SUSPECTED';
    await this.prisma.defacementSnapshot.update({
      where: { websiteId },
      data: {
        domain: host,
        url,
        title: current.title,
        titleHash: current.titleHash,
        contentHash: current.contentHash,
        structuralHash: current.structuralHash,
        textLength: current.textLength,
        assetCount: current.assetCount,
        formCount: current.formCount,
        scriptCount: current.scriptCount,
        keywordHits: current.keywordHits,
        status: assessment.status,
        changeScore: assessment.score,
        changeReasons: assessment.reasons,
        previousTitle: changed ? previous.title : previous.previousTitle,
        previousContentHash: changed ? previous.contentHash : previous.previousContentHash,
        lastChangedAt: changed ? new Date() : previous.lastChangedAt,
        lastCheckedAt: new Date(),
      },
    });

    if (assessment.status === 'SUSPECTED') {
      await this.alerts.checkDefacementChange(host, assessment.score, assessment.reasons, websiteId);
    }
  }

  private readDefacementFingerprint(result: CmsDetectionResult): DefacementFingerprint | null {
    const raw = result.rawSignals || {};
    const contentHash = raw['_deface_content_hash'];
    if (!contentHash) return null;

    const toNumber = (key: string) => {
      const value = Number(raw[key] || 0);
      return Number.isFinite(value) ? value : 0;
    };

    return {
      title: result.pageTitle,
      titleHash: raw['_deface_title_hash'] || null,
      contentHash,
      structuralHash: raw['_deface_structure_hash'] || null,
      textLength: toNumber('_deface_text_length'),
      assetCount: toNumber('_deface_asset_count'),
      formCount: toNumber('_deface_form_count'),
      scriptCount: toNumber('_deface_script_count'),
      keywordHits: (raw['_deface_keywords'] || '')
        .split(',')
        .map(item => item.trim())
        .filter(Boolean),
    };
  }

  private assessDefacement(
    previous: {
      titleHash: string | null;
      contentHash: string;
      structuralHash: string | null;
      textLength: number;
      assetCount: number;
      formCount: number;
      scriptCount: number;
    },
    current: DefacementFingerprint,
    httpStatus: number | null,
  ): { status: 'STABLE' | 'CHANGED' | 'SUSPECTED'; score: number; reasons: string[] } {
    let score = 0;
    const reasons: string[] = [];
    const contentChanged = previous.contentHash !== current.contentHash;

    if (current.keywordHits.length) {
      score += 90;
      reasons.push(`Defacement keyword: ${current.keywordHits.slice(0, 3).join(', ')}`);
    }

    if (contentChanged) {
      score += 30;
      reasons.push('Asosiy kontent hash o\'zgardi');
    }

    if (previous.structuralHash && current.structuralHash && previous.structuralHash !== current.structuralHash) {
      score += 15;
      reasons.push('DOM/asset tuzilmasi o\'zgardi');
    }

    if (previous.titleHash && current.titleHash && previous.titleHash !== current.titleHash) {
      score += 18;
      reasons.push('Sahifa title o\'zgardi');
    }

    const maxLength = Math.max(previous.textLength || 0, current.textLength || 0, 1);
    const textDeltaPct = Math.abs((previous.textLength || 0) - (current.textLength || 0)) / maxLength;
    if (contentChanged && textDeltaPct >= 0.6) {
      score += 22;
      reasons.push('Matn hajmi keskin o\'zgardi');
    } else if (contentChanged && textDeltaPct >= 0.35) {
      score += 12;
      reasons.push('Matn hajmi sezilarli o\'zgardi');
    }

    if (current.formCount > previous.formCount + 1) {
      score += 8;
      reasons.push('Yangi formalar paydo bo\'ldi');
    }

    if (Math.abs(current.assetCount - previous.assetCount) >= 12) {
      score += 8;
      reasons.push('Assetlar soni keskin o\'zgardi');
    }

    if (Math.abs(current.scriptCount - previous.scriptCount) >= 8) {
      score += 8;
      reasons.push('Scriptlar soni keskin o\'zgardi');
    }

    if (httpStatus !== null && httpStatus >= 500 && contentChanged) {
      score += 8;
      reasons.push(`HTTP ${httpStatus}`);
    }

    if (!contentChanged && !current.keywordHits.length) {
      return { status: 'STABLE', score: 0, reasons: [] };
    }

    const capped = Math.min(100, score);
    const status = capped >= 65 ? 'SUSPECTED' : capped >= 35 ? 'CHANGED' : 'STABLE';
    return { status, score: capped, reasons: status === 'STABLE' ? [] : reasons.slice(0, 6) };
  }

  // ── CAN EMBED ─────────────────────────────────────────────────────────────
  async checkCanEmbed(url: string): Promise<{ canEmbed: boolean }> {
    try {
      const res = await axios.head(url, {
        timeout: 8000,
        maxRedirects: 5,
        validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
      });
      const xfo = (res.headers['x-frame-options'] || '').toLowerCase().trim();
      const csp = res.headers['content-security-policy'] || '';
      const blocked =
        xfo === 'deny' ||
        xfo === 'sameorigin' ||
        (/frame-ancestors/i.test(csp) && !/frame-ancestors\s+\*/i.test(csp));
      return { canEmbed: !blocked };
    } catch {
      return { canEmbed: false };
    }
  }

  // ── LATEST RESULTS ────────────────────────────────────────────────────────
  async getLatestResults() {
    const rows = await this.prisma.scanResult.findMany({
      distinct: ['websiteId'],
      orderBy: { scannedAt: 'desc' },
      include: {
        website: {
          include: {
            _count: { select: { nucleiResults: true } },
          },
        },
      },
    });

    return rows.map(row => {
      const { _count, ...website } = row.website;
      return {
        ...row,
        website: {
          ...website,
          cveFindingsCount: _count.nucleiResults,
        },
      };
    });
  }

  // ── CSV EXPORT ────────────────────────────────────────────────────────────
  async exportCsv(): Promise<string> {
    const results = await this.getLatestResults();
    const esc = (v: string | null | undefined) =>
      v ? `"${String(v).replace(/"/g, '""')}"` : '';

    const header = 'URL,Label,CMS,Version,Category,Confidence,HTTP Status,Page Title,Server Tech,JS Frameworks,Scanned At,Error\n';
    const rows = results.map(r => [
      esc(r.website?.url),
      esc(r.website?.label),
      esc(r.cms),
      esc(r.version),
      esc(r.category),
      r.confidence?.toString() ?? '',
      r.httpStatus?.toString() ?? '',
      esc(r.pageTitle),
      esc(r.serverTech?.join('; ')),
      esc(r.jsFrameworks?.join('; ')),
      esc(r.scannedAt?.toISOString()),
      esc(r.errorMessage),
    ].join(','));

    return header + rows.join('\n');
  }
}
