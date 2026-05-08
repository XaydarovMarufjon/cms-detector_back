import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import axios from 'axios';
import { PrismaService } from '../prisma/prisma.service';

const DELAY_MS = 700; // NVD rate-limit buffer

const DEFAULT_FEEDS = [
  { name: 'NVD (NIST)',            type: 'NVD',        url: null, apiKey: null, enabled: true  },
  { name: 'CISA KEV',              type: 'CISA_KEV',   url: null, apiKey: null, enabled: true  },
  { name: 'EPSS (FIRST.org)',      type: 'EPSS',       url: null, apiKey: null, enabled: true  },
  { name: 'OSV (Google)',          type: 'OSV',        url: null, apiKey: null, enabled: true  },
  { name: 'CIRCL CVE',             type: 'CIRCL',      url: null, apiKey: null, enabled: true  },
  { name: 'MITRE CVE',             type: 'MITRE_CVE',  url: null, apiKey: null, enabled: true  },
  { name: 'AlienVault OTX',        type: 'OTX',        url: null, apiKey: null, enabled: false },
  { name: 'VirusTotal',            type: 'VIRUSTOTAL', url: null, apiKey: null, enabled: false },
  { name: 'MISP',                  type: 'MISP',       url: null, apiKey: null, enabled: false },
] as const;

@Injectable()
export class ThreatIntelService implements OnModuleInit {
  private readonly logger = new Logger(ThreatIntelService.name);

  // In-memory KEV set for fast lookup
  private kevSet = new Set<string>();
  private kevLoaded = false;

  constructor(private readonly prisma: PrismaService) {}

  async onModuleInit() {
    await this.seedDefaultFeeds();
  }

  private async seedDefaultFeeds() {
    for (const feed of DEFAULT_FEEDS) {
      const existing = await this.prisma.threatFeed.findFirst({ where: { type: feed.type as any } });
      if (!existing) {
        await this.prisma.threatFeed.create({ data: feed as any });
        this.logger.log(`Seeded default feed: ${feed.name}`);
      }
    }
  }

  // ── FEEDS CRUD ────────────────────────────────────────────────────────────

  async getFeeds() {
    return this.prisma.threatFeed.findMany({ orderBy: { createdAt: 'asc' } });
  }

  async upsertFeed(data: {
    id?: string;
    name: string;
    type: string;
    url?: string;
    apiKey?: string;
    enabled?: boolean;
  }) {
    if (data.id) {
      return this.prisma.threatFeed.update({
        where: { id: data.id },
        data: {
          name:    data.name,
          url:     data.url ?? null,
          apiKey:  data.apiKey ?? null,
          enabled: data.enabled ?? true,
        },
      });
    }
    return this.prisma.threatFeed.create({
      data: {
        name:    data.name,
        type:    data.type as any,
        url:     data.url ?? null,
        apiKey:  data.apiKey ?? null,
        enabled: data.enabled ?? true,
      },
    });
  }

  async toggleFeed(id: string, enabled: boolean) {
    return this.prisma.threatFeed.update({ where: { id }, data: { enabled } });
  }

  async deleteFeed(id: string) {
    return this.prisma.threatFeed.delete({ where: { id } });
  }

  async configureFeed(id: string, data: { url?: string; apiKey?: string; name?: string }) {
    const feed = await this.prisma.threatFeed.update({
      where: { id },
      data: {
        ...(data.name   !== undefined && { name:   data.name }),
        ...(data.url    !== undefined && { url:    data.url    || null }),
        ...(data.apiKey !== undefined && { apiKey: data.apiKey || null }),
        enabled: true,
        lastStatus: null,
        lastError:  null,
      },
    });
    return feed;
  }

  // ── SYNC FEED ─────────────────────────────────────────────────────────────

  async syncFeed(id: string): Promise<{ synced: number; errors: number }> {
    const feed = await this.prisma.threatFeed.findUniqueOrThrow({ where: { id } });

    await this.prisma.threatFeed.update({
      where: { id },
      data:  { lastStatus: 'syncing', lastError: null },
    });

    try {
      let result = { synced: 0, errors: 0 };

      if (feed.type === 'CISA_KEV') {
        result = await this.syncCisaKev();
      } else {
        // For NVD/EPSS/OTX/VT/MISP — re-enrich all existing CVE IDs
        const cveIds = await this.getAllStoredCveIds();
        for (const cveId of cveIds) {
          try {
            await this.enrichFromFeed(feed, cveId);
            result.synced++;
          } catch { result.errors++; }
          await sleep(DELAY_MS);
        }
      }

      await this.prisma.threatFeed.update({
        where: { id },
        data:  { lastSync: new Date(), lastStatus: 'ok', lastError: null },
      });

      return result;
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      await this.prisma.threatFeed.update({
        where: { id },
        data:  { lastStatus: 'error', lastError: msg },
      });
      throw e;
    }
  }

  async syncAllFeeds() {
    const feeds = await this.prisma.threatFeed.findMany({ where: { enabled: true } });
    const results: Record<string, { synced: number; errors: number }> = {};
    for (const feed of feeds) {
      try {
        results[feed.id] = await this.syncFeed(feed.id);
      } catch { results[feed.id] = { synced: 0, errors: 1 }; }
    }
    return results;
  }

  // ── ENRICH CVE ────────────────────────────────────────────────────────────

  async enrichCve(cveId: string): Promise<any> {
    const feeds = await this.prisma.threatFeed.findMany({ where: { enabled: true } });

    let enrichment = await this.prisma.cveEnrichment.findUnique({ where: { cveId } });
    const sources: string[] = enrichment?.sources ? [...enrichment.sources] : [];
    let patch: Record<string, any> = {};

    for (const feed of feeds) {
      try {
        const data = await this.enrichFromFeed(feed, cveId);
        if (data) {
          Object.assign(patch, data);
          if (!sources.includes(feed.type)) sources.push(feed.type);
        }
        await sleep(300);
      } catch (e) {
        this.logger.warn(`Enrich ${cveId} via ${feed.type} failed: ${e}`);
      }
    }

    if (!Object.keys(patch).length) return enrichment;

    patch.sources = sources;
    patch.updatedAt = new Date();

    if (enrichment) {
      enrichment = await this.prisma.cveEnrichment.update({
        where: { cveId },
        data:  patch,
      });
    } else {
      enrichment = await this.prisma.cveEnrichment.create({
        data: { cveId, ...patch },
      });
    }

    return enrichment;
  }

  async enrichAllPending(): Promise<{ total: number; enriched: number; errors: number }> {
    const cveIds = await this.getAllStoredCveIds();
    let enriched = 0;
    let errors = 0;

    for (const cveId of cveIds) {
      try {
        await this.enrichCve(cveId);
        enriched++;
      } catch { errors++; }
    }

    return { total: cveIds.length, enriched, errors };
  }

  async getEnrichment(cveId: string) {
    return this.prisma.cveEnrichment.findUnique({ where: { cveId } });
  }

  async getEnrichmentsForCves(cveIds: string[]) {
    if (!cveIds.length) return new Map<string, any>();
    const list = await this.prisma.cveEnrichment.findMany({
      where: { cveId: { in: cveIds } },
    });
    return new Map(list.map(e => [e.cveId, e]));
  }

  // ── INTERNAL: per-feed enrichment ─────────────────────────────────────────

  private async enrichFromFeed(feed: any, cveId: string): Promise<Record<string, any> | null> {
    switch (feed.type) {
      case 'NVD':        return this.fetchNvd(cveId, feed.apiKey);
      case 'EPSS':       return this.fetchEpss(cveId);
      case 'CISA_KEV':   return this.checkKev(cveId);
      case 'OSV':        return this.fetchOsv(cveId);
      case 'CIRCL':      return this.fetchCircl(cveId);
      case 'MITRE_CVE':  return this.fetchMitreCve(cveId);
      case 'OTX':        return feed.apiKey ? this.fetchOtx(cveId, feed.apiKey) : null;
      case 'VIRUSTOTAL': return feed.apiKey ? this.fetchVirusTotal(cveId, feed.apiKey) : null;
      case 'MISP':       return (feed.url && feed.apiKey) ? this.fetchMisp(cveId, feed.url, feed.apiKey) : null;
      default:           return null;
    }
  }

  // ── NVD ───────────────────────────────────────────────────────────────────

  private async fetchNvd(cveId: string, apiKey?: string | null): Promise<Record<string, any> | null> {
    const headers: Record<string, string> = apiKey ? { apiKey } : {};
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;

    const { data } = await axios.get(url, { headers, timeout: 15000 });
    const vuln = data?.vulnerabilities?.[0]?.cve;
    if (!vuln) return null;

    const desc = (vuln.descriptions as any[])?.find((d: any) => d.lang === 'en')?.value ?? null;
    const refs = ((vuln.references as any[]) ?? []).map((r: any) => r.url as string).slice(0, 10);
    const cwes = ((vuln.weaknesses as any[]) ?? [])
      .flatMap((w: any) => (w.description as any[]) ?? [])
      .map((d: any) => d.value as string)
      .filter((v: string) => v.startsWith('CWE-'))
      .slice(0, 5);

    let cvssScore: number | null = null;
    let cvssVector: string | null = null;
    let cvssVersion: string | null = null;

    const m31 = vuln.metrics?.cvssMetricV31?.[0]?.cvssData;
    const m30 = vuln.metrics?.cvssMetricV30?.[0]?.cvssData;
    const m2  = vuln.metrics?.cvssMetricV2?.[0]?.cvssData;

    if (m31) { cvssScore = m31.baseScore; cvssVector = m31.vectorString; cvssVersion = '3.1'; }
    else if (m30) { cvssScore = m30.baseScore; cvssVector = m30.vectorString; cvssVersion = '3.0'; }
    else if (m2) { cvssScore = m2.baseScore; cvssVector = m2.vectorString; cvssVersion = '2.0'; }

    return { cvssScore, cvssVector, cvssVersion, description: desc, references: refs, cweIds: cwes };
  }

  // ── OSV (Google Open Source Vulnerabilities) ─────────────────────────────

  private async fetchOsv(cveId: string): Promise<Record<string, any> | null> {
    const url = `https://api.osv.dev/v1/vulns/${encodeURIComponent(cveId)}`;
    try {
      const { data } = await axios.get(url, { timeout: 12000 });
      if (!data?.id) return null;

      const aliases: string[] = (data.aliases ?? []).filter((a: string) => a !== cveId);
      const refs: string[] = ((data.references ?? []) as any[])
        .map((r: any) => r.url as string)
        .filter(Boolean)
        .slice(0, 10);
      const desc: string | null = data.details ?? data.summary ?? null;

      // Extract CVSS from severity if NVD hasn't provided it yet
      let cvssScore: number | null = null;
      let cvssVector: string | null = null;
      for (const sev of (data.severity ?? [])) {
        if (sev.type === 'CVSS_V3' && sev.score) {
          cvssVector = sev.score;
          // Parse base score from vector
          const match = sev.score.match(/\/(\d+\.\d+)$/);
          if (!match) {
            // Try CVSS:3.1/AV:N/.../9.8 pattern
            const bsMatch = String(sev.score).match(/(\d+\.\d+)$/);
            if (bsMatch) cvssScore = parseFloat(bsMatch[1]);
          } else {
            cvssScore = parseFloat(match[1]);
          }
          break;
        }
      }

      return {
        osvFound:   true,
        osvAliases: aliases,
        ...(desc                && { description: desc }),
        ...(refs.length         && { references: refs }),
        ...(cvssScore !== null  && { cvssScore }),
        ...(cvssVector !== null && { cvssVector }),
      };
    } catch (e: any) {
      if (e?.response?.status === 404) return { osvFound: false };
      throw e;
    }
  }

  // ── CIRCL CVE ─────────────────────────────────────────────────────────────

  private async fetchCircl(cveId: string): Promise<Record<string, any> | null> {
    const url = `https://cve.circl.lu/api/cveitem/${encodeURIComponent(cveId)}`;
    const { data } = await axios.get(url, { timeout: 12000 });
    if (!data) return null;

    const cna = data?.containers?.cna ?? {};

    // Description
    const desc: string | null =
      (cna.descriptions as any[])?.find((d: any) => d.lang === 'en')?.value ?? null;

    // References
    const refs: string[] = ((cna.references ?? []) as any[])
      .map((r: any) => r.url as string)
      .filter(Boolean)
      .slice(0, 10);

    // CWEs
    const cwes: string[] = ((cna.problemTypes ?? []) as any[])
      .flatMap((p: any) => (p.descriptions ?? []) as any[])
      .map((d: any) => d.cweId as string)
      .filter((v: string) => v?.startsWith('CWE-'))
      .slice(0, 5);

    // CVSS from metrics
    let cvssScore: number | null = null;
    let cvssVector: string | null = null;
    let cvssVersion: string | null = null;
    const metrics = cna.metrics ?? [];
    for (const m of metrics as any[]) {
      const v31 = m.cvssV3_1 ?? m.cvssV31;
      const v30 = m.cvssV3_0 ?? m.cvssV30;
      const v2  = m.cvssV2_0 ?? m.cvssV20;
      if (v31) { cvssScore = v31.baseScore; cvssVector = v31.vectorString; cvssVersion = '3.1'; break; }
      if (v30) { cvssScore = v30.baseScore; cvssVector = v30.vectorString; cvssVersion = '3.0'; break; }
      if (v2)  { cvssScore = v2.baseScore;  cvssVector = v2.vectorString;  cvssVersion = '2.0'; break; }
    }

    return {
      ...(desc                && { description: desc }),
      ...(refs.length         && { references: refs }),
      ...(cwes.length         && { cweIds: cwes }),
      ...(cvssScore !== null  && { cvssScore }),
      ...(cvssVector !== null && { cvssVector }),
      ...(cvssVersion !== null && { cvssVersion }),
    };
  }

  // ── MITRE CVE API ─────────────────────────────────────────────────────────

  private async fetchMitreCve(cveId: string): Promise<Record<string, any> | null> {
    const url = `https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`;
    const { data } = await axios.get(url, { timeout: 12000 });
    if (!data) return null;

    const cna = data?.containers?.cna ?? {};

    const desc: string | null =
      (cna.descriptions as any[])?.find((d: any) => d.lang === 'en')?.value ?? null;

    const refs: string[] = ((cna.references ?? []) as any[])
      .map((r: any) => r.url as string)
      .filter(Boolean)
      .slice(0, 10);

    const cwes: string[] = ((cna.problemTypes ?? []) as any[])
      .flatMap((p: any) => (p.descriptions ?? []) as any[])
      .map((d: any) => d.cweId as string)
      .filter((v: string) => v?.startsWith('CWE-'))
      .slice(0, 5);

    return {
      ...(desc        && { description: desc }),
      ...(refs.length && { references: refs }),
      ...(cwes.length && { cweIds: cwes }),
    };
  }

  // ── EPSS ──────────────────────────────────────────────────────────────────

  private async fetchEpss(cveId: string): Promise<Record<string, any> | null> {
    const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`;
    const { data } = await axios.get(url, { timeout: 10000 });
    const entry = data?.data?.[0];
    if (!entry) return null;
    return {
      epssScore:   parseFloat(entry.epss),
      epssPercent: parseFloat(entry.percentile),
    };
  }

  // ── CISA KEV ──────────────────────────────────────────────────────────────

  private async syncCisaKev(): Promise<{ synced: number; errors: number }> {
    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    const { data } = await axios.get(url, { timeout: 30000 });
    const vulns: any[] = data?.vulnerabilities ?? [];

    this.kevSet.clear();
    const kevMap = new Map<string, string>(); // cveId → dueDate
    for (const v of vulns) {
      this.kevSet.add(v.cveID);
      kevMap.set(v.cveID, v.dueDate ?? null);
    }
    this.kevLoaded = true;

    // Update existing enrichments
    let synced = 0;
    const existing = await this.prisma.cveEnrichment.findMany({ select: { cveId: true } });
    for (const e of existing) {
      const isKev = this.kevSet.has(e.cveId);
      const kevDueDate = kevMap.get(e.cveId) ?? null;
      await this.prisma.cveEnrichment.update({
        where: { cveId: e.cveId },
        data:  { isKev, kevDueDate },
      });
      synced++;
    }

    this.logger.log(`CISA KEV synced: ${this.kevSet.size} total KEV, updated ${synced} enrichments`);
    return { synced, errors: 0 };
  }

  private async checkKev(cveId: string): Promise<Record<string, any> | null> {
    if (!this.kevLoaded) {
      try { await this.syncCisaKev(); } catch { return null; }
    }
    return { isKev: this.kevSet.has(cveId) };
  }

  // ── AlienVault OTX ───────────────────────────────────────────────────────

  private async fetchOtx(cveId: string, apiKey: string): Promise<Record<string, any> | null> {
    const url = `https://otx.alienvault.com/api/v1/indicators/CVE/${encodeURIComponent(cveId)}/general`;
    const { data } = await axios.get(url, {
      headers: { 'X-OTX-API-KEY': apiKey },
      timeout: 15000,
    });
    const pulses = data?.pulse_info?.count ?? 0;
    return { otxPulses: pulses };
  }

  // ── VirusTotal ────────────────────────────────────────────────────────────

  private async fetchVirusTotal(cveId: string, apiKey: string): Promise<Record<string, any> | null> {
    const url = `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(cveId)}&limit=5`;
    const { data } = await axios.get(url, {
      headers: { 'x-apikey': apiKey },
      timeout: 15000,
    });
    const items: any[] = data?.data ?? [];
    const malicious = items.reduce((acc: number, item: any) => {
      return acc + (item?.attributes?.last_analysis_stats?.malicious ?? 0);
    }, 0);
    return { vtMalicious: malicious };
  }

  // ── MISP ──────────────────────────────────────────────────────────────────

  private async fetchMisp(cveId: string, baseUrl: string, apiKey: string): Promise<Record<string, any> | null> {
    const url = `${baseUrl.replace(/\/$/, '')}/attributes/restSearch`;
    const { data } = await axios.post(
      url,
      { returnFormat: 'json', value: cveId, type: 'vulnerability', limit: 100 },
      {
        headers: { Authorization: apiKey, Accept: 'application/json', 'Content-Type': 'application/json' },
        timeout: 15000,
        httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
      },
    );
    const attrs: any[] = data?.response?.Attribute ?? [];
    return { mispEvents: attrs.length };
  }

  // ── HELPERS ───────────────────────────────────────────────────────────────

  private async getAllStoredCveIds(): Promise<string[]> {
    const rows = await this.prisma.nucleiResult.findMany({
      where:  { cveId: { not: null } },
      select: { cveId: true },
      distinct: ['cveId'],
    });
    return rows.map(r => r.cveId).filter(Boolean) as string[];
  }
}

function sleep(ms: number) {
  return new Promise(r => setTimeout(r, ms));
}
