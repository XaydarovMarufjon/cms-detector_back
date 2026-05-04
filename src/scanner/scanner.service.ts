// src/scanner/scanner.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import axios from 'axios';
import { PrismaService } from '../prisma/prisma.service';
import { CmsDetectorService } from './cms-detector.service';
import { WhoisService } from './whois.service';
import { SiteInfoService } from './site-info.service';
import { AlertsService } from '../alerts/alerts.service';
import pLimit from 'p-limit';

@Injectable()
export class ScannerService {
  private readonly logger = new Logger(ScannerService.name);
  private currentInterval = 60; // daqiqa (default: 1 soat)

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

  // ── DEFAULT CRON ─────────────────────────────────────────────────────────
  private startDefaultJob() {
    const job = new CronJob(`0 */${this.currentInterval} * * * *`, () => {
      this.logger.log(`Auto scan started (every ${this.currentInterval} min)`);
      this.scanAll();
    });
    this.scheduler.addCronJob('auto-scan', job);
    job.start();
    this.logger.log(`✅ Auto scan started: every ${this.currentInterval} minutes`);
  }

  // ── INTERVAL SOZLASH (dashboard dan) ──────────────────────────────────────
  setInterval(minutes: number) {
    this.currentInterval = minutes;

    try {
      const job = this.scheduler.getCronJob('auto-scan');
      job.stop();
      this.scheduler.deleteCronJob('auto-scan');
    } catch { }

    // Maxsus intervallar
    let cronExpr: string;
    if (minutes < 60) {
      cronExpr = `0 */${minutes} * * * *`;          // daqiqada
    } else if (minutes === 60) {
      cronExpr = `0 0 * * * *`;                     // har soat
    } else if (minutes === 360) {
      cronExpr = `0 0 */6 * * *`;                   // har 6 soat
    } else if (minutes === 720) {
      cronExpr = `0 0 */12 * * *`;                  // har 12 soat
    } else {
      cronExpr = `0 0 0 * * *`;                     // har kun
    }

    const newJob = new CronJob(cronExpr, () => {
      this.logger.log(`Auto scan (every ${minutes} min)`);
      this.scanAll();
    });

    this.scheduler.addCronJob('auto-scan', newJob);
    newJob.start();
    this.logger.log(`✅ Interval yangilandi: ${minutes} daqiqa`);
    return { interval: minutes, cronExpr, message: `Har ${minutes} daqiqada skanerlash` };
  }

  getInterval() {
    return { interval: this.currentInterval };
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

  // ── SCAN ALL ──────────────────────────────────────────────────────────────


  async scanAll() {
    const sites = await this.prisma.website.findMany();
    const limit = pLimit(10); // bir vaqtning o‘zida 10 ta

    return Promise.all(
      sites.map(site =>
        limit(() => this.scanOne(site.id, site.url))
      )
    );
  }

  // ── SCAN ONE ──────────────────────────────────────────────────────────────
  async scanOne(websiteId: string, url: string) {
    const host = this.extractHost(url);
    try {
      const result = await this.detector.detect(url);
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
    return this.prisma.scanResult.findMany({
      distinct: ['websiteId'],
      orderBy: { scannedAt: 'desc' },
      include: { website: true },
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