import { Injectable, Logger, forwardRef, Inject } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { writeFile, unlink } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomUUID } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { ThreatIntelService } from './threat-intel.service';

const execFileAsync = promisify(execFile);

export interface NucleiHit {
  templateId:  string;
  cveId:       string | null;
  severity:    string;
  name:        string;
  description: string | null;
  matchedAt:   string | null;
  subdomain:   string;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5,
};

const NUCLEI_BINS = [
  'nuclei',
  '/usr/local/bin/nuclei',
  '/usr/bin/nuclei',
  `${process.env['HOME']}/go/bin/nuclei`,
  `${process.env['HOME']}/.local/bin/nuclei`,
];

export interface NucleiScanProgress {
  scanning:     boolean;
  currentSite:  string | null;
  currentIndex: number;
  total:        number;
  completed: Array<{
    url:      string;
    label:    string | null;
    findings: number;
    error:    string | null;
  }>;
  startedAt: string | null;
}

@Injectable()
export class NucleiService {
  private readonly logger = new Logger(NucleiService.name);
  private nucleiInterval = 1440; // daqiqa (default: 24 soat)
  private scanningAll = false;

  private progress: NucleiScanProgress = {
    scanning: false, currentSite: null, currentIndex: 0,
    total: 0, completed: [], startedAt: null,
  };

  constructor(
    private readonly prisma:       PrismaService,
    private readonly scheduler:    SchedulerRegistry,
    private readonly threatIntel:  ThreatIntelService,
  ) {
    this.startScheduledJob();
  }

  // ── SCHEDULER ────────────────────────────────────────────────────────────

  private startScheduledJob() {
    const cronExpr = this.toCronExpr(this.nucleiInterval);
    const job = new CronJob(cronExpr, () => {
      this.logger.log(`Nuclei auto-scan started (every ${this.nucleiInterval} min)`);
      this.scanAllWebsites().catch(e => this.logger.error('Nuclei auto-scan failed', e));
    });
    this.scheduler.addCronJob('nuclei-scan', job);
    job.start();
    this.logger.log(`✅ Nuclei auto-scan started: every ${this.nucleiInterval} minutes`);
  }

  setNucleiInterval(minutes: number) {
    this.nucleiInterval = minutes;

    try {
      const job = this.scheduler.getCronJob('nuclei-scan');
      job.stop();
      this.scheduler.deleteCronJob('nuclei-scan');
    } catch { /* not registered yet */ }

    const cronExpr = this.toCronExpr(minutes);
    const newJob = new CronJob(cronExpr, () => {
      this.logger.log(`Nuclei auto-scan (every ${minutes} min)`);
      this.scanAllWebsites().catch(e => this.logger.error('Nuclei auto-scan failed', e));
    });
    this.scheduler.addCronJob('nuclei-scan', newJob);
    newJob.start();
    this.logger.log(`✅ Nuclei interval yangilandi: ${minutes} daqiqa`);
    return { interval: minutes, cronExpr, message: `Har ${minutes} daqiqada nuclei skan` };
  }

  getNucleiInterval() {
    return { interval: this.nucleiInterval };
  }

  private toCronExpr(minutes: number): string {
    if (minutes < 60)   return `0 */${minutes} * * * *`;
    if (minutes === 60) return `0 0 * * * *`;
    if (minutes === 360)  return `0 0 */6 * * *`;
    if (minutes === 720)  return `0 0 */12 * * *`;
    return `0 0 0 * * *`; // kunlik (default >=1440)
  }

  // ── SCAN ALL WEBSITES ─────────────────────────────────────────────────────

  getProgress(): NucleiScanProgress {
    return { ...this.progress, completed: [...this.progress.completed] };
  }

  async scanAllWebsites(): Promise<{ total: number; findings: number }> {
    if (this.scanningAll) {
      this.logger.warn('Nuclei scan already running, skipping');
      return { total: 0, findings: 0 };
    }
    this.scanningAll = true;

    const websites = await this.prisma.website.findMany();
    this.progress = {
      scanning: true, currentSite: null, currentIndex: 0,
      total: websites.length, completed: [],
      startedAt: new Date().toISOString(),
    };

    try {
      // Build url→websiteId map
      const urlMap = new Map<string, { id: string; label: string | null }>();
      for (const site of websites) {
        urlMap.set(site.url, { id: site.id, label: site.label ?? null });
        // also map hostname variant
        try {
          const host = new URL(site.url).hostname;
          urlMap.set(host, { id: site.id, label: site.label ?? null });
        } catch { /* ignore */ }
      }

      const targets = websites.map(s => s.url);

      // Show first site as "current" while full scan runs
      this.progress.currentSite  = `${websites.length} ta sayt skanlanmoqda...`;
      this.progress.currentIndex = 0;

      // Delete old results for all websites
      await this.prisma.nucleiResult.deleteMany({
        where: { websiteId: { in: websites.map(s => s.id) } },
      });

      // Single nuclei invocation for all targets
      const hits = await this.runNuclei(targets);

      // Group hits by websiteId
      const byWebsite = new Map<string, NucleiHit[]>();
      for (const hit of hits) {
        const match =
          urlMap.get(hit.subdomain) ??
          urlMap.get(`https://${hit.subdomain}`) ??
          urlMap.get(`http://${hit.subdomain}`);
        if (!match) continue;
        if (!byWebsite.has(match.id)) byWebsite.set(match.id, []);
        byWebsite.get(match.id)!.push(hit);
      }

      // Save to DB
      if (hits.length) {
        await this.prisma.$transaction(
          hits.map(h => {
            const match =
              urlMap.get(h.subdomain) ??
              urlMap.get(`https://${h.subdomain}`) ??
              urlMap.get(`http://${h.subdomain}`);
            const websiteId = match?.id ?? websites[0].id;
            return this.prisma.nucleiResult.create({
              data: {
                websiteId,
                subdomain:   h.subdomain,
                templateId:  h.templateId,
                cveId:       h.cveId,
                severity:    h.severity,
                name:        h.name,
                description: h.description,
                matchedAt:   h.matchedAt,
              },
            });
          }),
        );
      }

      // Build completed list
      for (const site of websites) {
        const findings = byWebsite.get(site.id)?.length ?? 0;
        this.progress.completed.push({
          url:   site.url,
          label: site.label ?? null,
          findings,
          error: null,
        });
      }
      this.progress.currentIndex = websites.length;

      // Auto-enrich found CVEs (non-blocking)
      const cveIds = [...new Set(hits.map(h => h.cveId).filter(Boolean))] as string[];
      if (cveIds.length) {
        this.enrichCvesBackground(cveIds);
      }

      this.logger.log(`Nuclei scan-all done: ${websites.length} sites, ${hits.length} findings`);
      return { total: websites.length, findings: hits.length };
    } catch (e) {
      this.logger.error(`Nuclei scan-all failed: ${String(e)}`);
      throw e;
    } finally {
      this.scanningAll = false;
      this.progress.scanning    = false;
      this.progress.currentSite = null;
    }
  }

  // ── GET ALL RESULTS ───────────────────────────────────────────────────────

  async getAllResults(): Promise<any[]> {
    return this.fetchWithEnrichment('PENDING');
  }

  async getMonitoringResults(): Promise<any[]> {
    return this.fetchWithEnrichment('CONFIRMED');
  }

  async getRejectedResults(): Promise<any[]> {
    return this.fetchWithEnrichment('FALSE_POSITIVE');
  }

  private async fetchWithEnrichment(status: string): Promise<any[]> {
    const rows = await this.prisma.nucleiResult.findMany({
      where:   { status: status as any },
      include: { website: { select: { url: true, label: true } } },
      orderBy: { scannedAt: 'desc' },
    });

    const cveIds = [...new Set(rows.map(r => r.cveId).filter(Boolean))] as string[];
    const enrichMap = await this.threatIntel.getEnrichmentsForCves(cveIds);

    return rows
      .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5))
      .map(r => ({ ...r, enrichment: r.cveId ? (enrichMap.get(r.cveId) ?? null) : null }));
  }

  async updateCveStatus(id: string, status: 'PENDING' | 'FALSE_POSITIVE' | 'CONFIRMED'): Promise<any> {
    return this.prisma.nucleiResult.update({
      where: { id },
      data:  { status },
    });
  }

  // ── SCAN (per website) ────────────────────────────────────────────────────

  async scan(
    websiteId: string,
    subdomains: string[],
    replaceExisting = false,
  ): Promise<NucleiHit[]> {
    if (!subdomains.length) return [];

    const targets = subdomains.map(s =>
      s.startsWith('http') ? s : `https://${s}`,
    );

    const hits = await this.runNuclei(targets);

    if (replaceExisting) {
      await this.prisma.nucleiResult.deleteMany({ where: { websiteId } });
    }

    if (hits.length) {
      await this.prisma.$transaction(
        hits.map(h =>
          this.prisma.nucleiResult.create({
            data: {
              websiteId,
              subdomain:   h.subdomain,
              templateId:  h.templateId,
              cveId:       h.cveId,
              severity:    h.severity,
              name:        h.name,
              description: h.description,
              matchedAt:   h.matchedAt,
            },
          }),
        ),
      );
    }

    // Auto-enrich found CVEs (non-blocking)
    const cveIds = [...new Set(hits.map(h => h.cveId).filter(Boolean))] as string[];
    if (cveIds.length) this.enrichCvesBackground(cveIds);

    return hits;
  }

  private enrichCvesBackground(cveIds: string[]) {
    (async () => {
      for (const cveId of cveIds) {
        try { await this.threatIntel.enrichCve(cveId); } catch { /* ignore */ }
      }
    })().catch(() => {});
  }

  // ── GET RESULTS (per website) ─────────────────────────────────────────────

  async getResults(websiteId: string): Promise<any[]> {
    const rows = await this.prisma.nucleiResult.findMany({
      where:   { websiteId },
      orderBy: { scannedAt: 'desc' },
    });
    return rows.sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5),
    );
  }

  // ── NUCLEI BINARY ─────────────────────────────────────────────────────────

  private async runNuclei(targets: string[]): Promise<NucleiHit[]> {
    const tmpFile = join(tmpdir(), `nuclei-${randomUUID()}.txt`);
    try {
      await writeFile(tmpFile, targets.join('\n'), 'utf8');

      // 3 min per target, min 5 min
      const timeoutMs = Math.max(300_000, targets.length * 180_000);

      for (const bin of NUCLEI_BINS) {
        try {
          const { stdout } = await execFileAsync(
            bin,
            [
              '-list',    tmpFile,
              '-tags',    'cve',
              '-j',               // JSONL output (nuclei v3)
              '-silent',
              '-no-color',
              '-timeout', '10',
              '-rl',      '100',  // rate-limit req/s
              '-bs',      '25',   // bulk-size
              '-c',       '25',   // concurrency
            ],
            { timeout: timeoutMs },
          );
          return this.parse(stdout);
        } catch (err: any) {
          if (err?.code === 'ENOENT') continue;
          this.logger.warn(`nuclei error: ${String(err)}`);
          if (err?.stdout) return this.parse(err.stdout as string);
          return [];
        }
      }
      throw new Error(
        'nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
      );
    } finally {
      await unlink(tmpFile).catch(() => {});
    }
  }

  private parse(stdout: string): NucleiHit[] {
    const hits: NucleiHit[] = [];
    for (const line of stdout.split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        const obj       = JSON.parse(t);
        const info      = (obj['info'] as any) ?? {};
        const cveIds: string[] = info?.classification?.['cve-id'] ?? [];
        const templateId: string = obj['template-id'] ?? obj['template'] ?? '';

        if (!cveIds.length && !templateId.toUpperCase().startsWith('CVE')) continue;

        const matchedAt: string = obj['matched-at'] ?? obj['host'] ?? '';
        hits.push({
          templateId,
          cveId:       cveIds[0] ?? null,
          severity:    info['severity'] ?? 'unknown',
          name:        info['name'] ?? templateId,
          description: info['description'] ?? null,
          matchedAt:   matchedAt || null,
          subdomain:   this.extractHost(matchedAt),
        });
      } catch { /* skip non-JSON */ }
    }
    return hits;
  }

  private extractHost(url: string): string {
    try   { return new URL(url).hostname; }
    catch { return url.replace(/^https?:\/\//, '').split('/')[0]; }
  }
}
