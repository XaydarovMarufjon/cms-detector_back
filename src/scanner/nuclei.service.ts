import { Injectable, InternalServerErrorException, Logger, forwardRef, Inject } from '@nestjs/common';
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
import { CveCorrelationService } from './cve-correlation.service';

const execFileAsync = promisify(execFile);

export interface NucleiHit {
  websiteId?:    string;
  templateId:  string;
  cveId:       string | null;
  severity:    string;
  name:        string;
  description: string | null;
  matchedAt:   string | null;
  subdomain:   string;
  source?:      string;
  confidence?:  number;
  referenceUrl?: string | null;
  evidence?:    Record<string, any>;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5,
};

const NUCLEI_BINS = [
  'nuclei',
  '/opt/homebrew/bin/nuclei',
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
  private subdomainScanQueue: Promise<void> = Promise.resolve();
  private queuedSubdomainScans = new Set<string>();

  private progress: NucleiScanProgress = {
    scanning: false, currentSite: null, currentIndex: 0,
    total: 0, completed: [], startedAt: null,
  };

  constructor(
    private readonly prisma:       PrismaService,
    private readonly scheduler:    SchedulerRegistry,
    private readonly threatIntel:  ThreatIntelService,
    private readonly cveCorrelation: CveCorrelationService,
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

      const targets = this.normalizeTargets(websites.map(s => s.url));
      const targetsByWebsite = new Map<string, string[]>(websites.map(site => [site.id, [site.url]]));

      // Show first site as "current" while full scan runs
      this.progress.currentSite  = `${websites.length} ta sayt skanlanmoqda...`;
      this.progress.currentIndex = 0;

      // Delete old results for all websites
      await this.prisma.nucleiResult.deleteMany({
        where: { websiteId: { in: websites.map(s => s.id) } },
      });

      // Single nuclei invocation for all targets. If the binary is missing or
      // templates fail, keep passive CVE correlation working from stored scan data.
      let nucleiHits: NucleiHit[] = [];
      try {
        nucleiHits = await this.runNuclei(targets);
      } catch (err) {
        this.logger.warn(`Nuclei active scan failed, passive CVE lookup will continue: ${String(err)}`);
      }

      const passiveHits = await this.cveCorrelation.correlateWebsites(
        websites.map(site => site.id),
        targetsByWebsite,
      );
      const hits = this.mergeHits([...nucleiHits, ...passiveHits]);
      const resolveWebsiteId = (hit: NucleiHit): string | null => {
        const match =
          urlMap.get(hit.subdomain) ??
          urlMap.get(`https://${hit.subdomain}`) ??
          urlMap.get(`http://${hit.subdomain}`);
        return hit.websiteId ?? match?.id ?? null;
      };

      // Group hits by websiteId
      const byWebsite = new Map<string, NucleiHit[]>();
      for (const hit of hits) {
        const websiteId = resolveWebsiteId(hit);
        if (!websiteId) continue;
        if (!byWebsite.has(websiteId)) byWebsite.set(websiteId, []);
        byWebsite.get(websiteId)!.push(hit);
      }

      // Save to DB
      const rows = hits
        .map(h => {
          const websiteId = resolveWebsiteId(h);
          return websiteId ? this.toNucleiCreateRow(h, websiteId) : null;
        })
        .filter((row): row is ReturnType<NucleiService['toNucleiCreateRow']> => !!row);
      if (rows.length) await this.prisma.nucleiResult.createMany({ data: rows });

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
      await this.markCveScansCompleted(websites.map(site => site.id));

      // Auto-enrich found CVEs (non-blocking)
      const cveIds = [...new Set(hits.map(h => h.cveId).filter(Boolean))] as string[];
      if (cveIds.length) {
        this.enrichCvesBackground(cveIds);
      }

      this.logger.log(`Nuclei scan-all done: ${websites.length} sites, ${rows.length} findings`);
      return { total: websites.length, findings: rows.length };
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
    replaceExisting = true,
  ): Promise<NucleiHit[]> {
    if (!subdomains.length) {
      const website = await this.prisma.website.findUnique({ where: { id: websiteId } });
      if (website?.url) subdomains = [website.url];
    }
    if (!subdomains.length) return [];

    const targets = this.expandTargets(subdomains);

    let nucleiHits: NucleiHit[] = [];
    try {
      nucleiHits = await this.runNuclei(targets);
    } catch (err) {
      this.logger.warn(`Nuclei active scan failed for ${websiteId}, passive CVE lookup will continue: ${String(err)}`);
    }
    const passiveHits = await this.cveCorrelation.correlateWebsite(websiteId, targets);
    const hits = this.mergeHits([...nucleiHits, ...passiveHits]);

    if (replaceExisting) {
      await this.prisma.nucleiResult.deleteMany({ where: { websiteId } });
    }

    if (hits.length) {
      await this.prisma.nucleiResult.createMany({
        data: hits.map(h => this.toNucleiCreateRow(h, websiteId)),
      });
    }
    await this.markCveScanCompleted(websiteId);

    // Auto-enrich found CVEs (non-blocking)
    const cveIds = [...new Set(hits.map(h => h.cveId).filter(Boolean))] as string[];
    if (cveIds.length) this.enrichCvesBackground(cveIds);

    return hits;
  }

  queueSubdomainScan(
    websiteId: string,
    rootDomain: string,
    subdomains: string[],
    reason = 'subdomain-discovery',
  ) {
    const hosts = this.normalizeHosts(subdomains);
    const domain = this.normalizeHost(rootDomain);
    const key = `${websiteId}:${domain || hosts.join(',')}`;
    if (!websiteId || this.queuedSubdomainScans.has(key)) return;

    this.queuedSubdomainScans.add(key);
    const job = this.subdomainScanQueue
      .then(async () => {
        const hits = await this.scanSubdomainTargets(websiteId, hosts, domain);
        this.logger.log(`Nuclei ${reason} scan done for ${domain || websiteId}: ${hosts.length} alive subdomain(s), ${hits.length} finding(s)`);
      })
      .catch(err => {
        this.logger.warn(`Nuclei ${reason} scan failed for ${domain || websiteId}: ${String(err)}`);
      })
      .finally(() => {
        this.queuedSubdomainScans.delete(key);
      });

    this.subdomainScanQueue = job.then(() => undefined, () => undefined);
  }

  async scanSubdomainTargets(
    websiteId: string,
    subdomains: string[],
    rootDomain?: string,
  ): Promise<NucleiHit[]> {
    const hosts = this.normalizeHosts(subdomains);
    const domain = rootDomain ? this.normalizeHost(rootDomain) : '';

    await this.clearSubdomainResults(websiteId, hosts, domain);
    if (!hosts.length) {
      await this.markCveScanCompleted(websiteId);
      return [];
    }

    const targets = this.expandTargets(hosts);

    let nucleiHits: NucleiHit[] = [];
    try {
      nucleiHits = await this.runNuclei(targets);
    } catch (err) {
      this.logger.warn(`Nuclei active subdomain scan failed for ${websiteId}, passive CVE lookup will continue: ${String(err)}`);
    }

    const passiveHits = await this.cveCorrelation.correlateWebsite(websiteId, targets);
    const targetHosts = new Set(hosts);
    const hits = this.mergeHits([...nucleiHits, ...passiveHits])
      .filter(hit => targetHosts.has(this.normalizeHost(hit.subdomain)));

    if (hits.length) {
      await this.prisma.nucleiResult.createMany({
        data: hits.map(h => this.toNucleiCreateRow(h, websiteId)),
      });
    }
    await this.markCveScanCompleted(websiteId);

    const cveIds = [...new Set(hits.map(h => h.cveId).filter(Boolean))] as string[];
    if (cveIds.length) this.enrichCvesBackground(cveIds);

    return hits;
  }

  private async clearSubdomainResults(websiteId: string, subdomains: string[], rootDomain: string) {
    const hosts = this.normalizeHosts(subdomains);
    const or: Array<{ subdomain: { in: string[] } } | { subdomain: { endsWith: string } }> = [];
    if (hosts.length) or.push({ subdomain: { in: hosts } });
    if (rootDomain) or.push({ subdomain: { endsWith: `.${rootDomain}` } });
    if (!or.length) return;

    await this.prisma.nucleiResult.deleteMany({
      where: {
        websiteId,
        OR: or,
      },
    });
  }

  private async markCveScanCompleted(websiteId: string) {
    try {
      await this.prisma.website.update({
        where: { id: websiteId },
        data: { cveScannedAt: new Date() },
      });
    } catch (err) {
      this.logger.warn(`CVE scan completion save failed for ${websiteId}: ${String(err)}`);
    }
  }

  private async markCveScansCompleted(websiteIds: string[]) {
    if (!websiteIds.length) return;
    try {
      await this.prisma.website.updateMany({
        where: { id: { in: websiteIds } },
        data: { cveScannedAt: new Date() },
      });
    } catch (err) {
      this.logger.warn(`CVE scan completion save failed: ${String(err)}`);
    }
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

  private toNucleiCreateRow(h: NucleiHit, websiteId: string) {
    return {
      websiteId,
      subdomain:   h.subdomain,
      templateId:  h.templateId,
      cveId:       h.cveId,
      severity:    h.severity,
      name:        h.name,
      description: h.description,
      matchedAt:   h.matchedAt,
      source:      h.source ?? 'NUCLEI',
      confidence:  h.confidence ?? 95,
      referenceUrl: h.referenceUrl ?? null,
      evidence:    h.evidence ?? {},
    };
  }

  // ── NUCLEI BINARY ─────────────────────────────────────────────────────────

  private async runNuclei(targets: string[]): Promise<NucleiHit[]> {
    if (!targets.length) return [];

    const tmpFile = join(tmpdir(), `nuclei-${randomUUID()}.txt`);
    try {
      await writeFile(tmpFile, targets.join('\n'), 'utf8');

      const perTargetMs = Math.min(180_000, Math.max(20_000, Number(process.env['NUCLEI_TARGET_TIMEOUT_MS'] || 45_000)));
      const minTimeoutMs = Math.min(120_000, Math.max(20_000, Number(process.env['NUCLEI_MIN_TIMEOUT_MS'] || 45_000)));
      const maxTimeoutMs = Math.min(30 * 60_000, Math.max(minTimeoutMs, Number(process.env['NUCLEI_MAX_TIMEOUT_MS'] || 15 * 60_000)));
      const timeoutMs = Math.min(maxTimeoutMs, Math.max(minTimeoutMs, targets.length * perTargetMs));

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
              '-retries', '1',
              '-rl',      '100',  // rate-limit req/s
              '-bs',      '25',   // bulk-size
              '-c',       '25',   // concurrency
              '-or',              // omit raw request/response from JSONL
              '-duc',             // disable update checks in API-triggered scans
              '-no-stdin',
            ],
            { timeout: timeoutMs, maxBuffer: 20 * 1024 * 1024 },
          );
          return this.parse(stdout);
        } catch (err: any) {
          if (err?.code === 'ENOENT') continue;
          this.logger.warn(`nuclei error: ${String(err)}`);
          const hits = err?.stdout ? this.parse(err.stdout as string) : [];
          if (hits.length) return hits;
          throw new InternalServerErrorException(this.formatNucleiError(err));
        }
      }
      throw new InternalServerErrorException(
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
          source:      'NUCLEI',
          confidence:  95,
          referenceUrl: null,
          evidence: {
            templateId,
            matcherName: obj['matcher-name'] ?? null,
            templateUrl: obj['template-url'] ?? null,
            type: obj['type'] ?? null,
          },
        });
      } catch { /* skip non-JSON */ }
    }
    return hits;
  }

  private mergeHits(hits: NucleiHit[]): NucleiHit[] {
    const rank: Record<string, number> = { NUCLEI: 0, LOCAL_RULE: 1, OSV: 2, NVD: 3 };
    const map = new Map<string, NucleiHit>();
    for (const hit of hits) {
      const key = `${hit.websiteId ?? ''}:${hit.subdomain}:${hit.cveId ?? hit.templateId}`;
      const current = map.get(key);
      if (!current) {
        map.set(key, hit);
        continue;
      }
      const currentRank = rank[current.source ?? 'NUCLEI'] ?? 9;
      const hitRank = rank[hit.source ?? 'NUCLEI'] ?? 9;
      if (hitRank < currentRank || (hit.confidence ?? 0) > (current.confidence ?? 0)) {
        map.set(key, hit);
      }
    }
    return [...map.values()];
  }

  private extractHost(url: string): string {
    try   { return new URL(url).hostname; }
    catch { return url.replace(/^https?:\/\//, '').split('/')[0]; }
  }

  private normalizeHost(value: string): string {
    return this.extractHost(value || '')
      .toLowerCase()
      .replace(/^www\./, '')
      .trim();
  }

  private normalizeHosts(values: string[]): string[] {
    return [...new Set(
      values
        .map(value => this.normalizeHost(value))
        .filter(Boolean),
    )];
  }

  private normalizeTargets(targets: string[]): string[] {
    return [...new Set(
      targets
        .map(t => t.trim())
        .filter(Boolean)
        .map(t => t.startsWith('http://') || t.startsWith('https://') ? t : `https://${t}`)
        .map(t => t.replace(/\/$/, '')),
    )];
  }

  private expandTargets(targets: string[]): string[] {
    const expanded = targets.flatMap(raw => {
      const t = raw.trim().replace(/\/$/, '');
      if (!t) return [];
      if (t.startsWith('http://') || t.startsWith('https://')) return [t];
      return [`https://${t}`, `http://${t}`];
    });
    return [...new Set(expanded)];
  }

  private formatNucleiError(err: any): string {
    const stderr = String(err?.stderr || '').trim();
    const message = String(err?.message || '').trim();
    const details = stderr || message || 'nuclei scan failed';
    return details.split('\n').slice(-4).join('\n');
  }
}
