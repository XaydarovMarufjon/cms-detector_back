import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import axios from 'axios';
import { PrismaService } from '../prisma/prisma.service';

type OsintSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

interface DorkPreset {
  category: string;
  label: string;
  severity: OsintSeverity;
  build: (site: string) => string;
}

interface ScanInput {
  domains?: string[];
  websiteIds?: string[];
  categories?: string[];
  limitPerQuery?: number;
}

interface ManualFindingInput {
  domain?: string;
  url: string;
  title?: string;
  evidence?: string;
  query?: string;
  category?: string;
  severity?: OsintSeverity;
}

interface SearchItem {
  link?: string;
  title?: string;
  snippet?: string;
  displayLink?: string;
}

const DORK_PRESETS: DorkPreset[] = [
  {
    category: 'personal_data',
    label: 'PINFL/JSHSHIR/passport',
    severity: 'HIGH',
    build: site => `${site} ("PINFL" OR "ПИНФЛ" OR "JSHSHIR" OR "ЖШШИР" OR "passport" OR "pasport" OR "паспорт") (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:csv)`,
  },
  {
    category: 'confidential_file',
    label: 'Maxfiy hujjatlar',
    severity: 'HIGH',
    build: site => `${site} ("maxfiy" OR "махфий" OR "confidential" OR "secret" OR "служебного пользования") (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:zip OR filetype:rar)`,
  },
  {
    category: 'secret_config',
    label: 'Config va credential izlari',
    severity: 'CRITICAL',
    build: site => `${site} (filetype:env OR filetype:log OR filetype:txt OR inurl:.env OR intext:"DB_PASSWORD" OR intext:"API_KEY" OR intext:"PRIVATE_KEY" OR intext:"password")`,
  },
  {
    category: 'backup_dump',
    label: 'Backup va dump fayllar',
    severity: 'CRITICAL',
    build: site => `${site} (filetype:sql OR filetype:bak OR filetype:backup OR filetype:dump OR filetype:zip OR filetype:tar OR filetype:gz OR inurl:backup OR inurl:dump OR inurl:db)`,
  },
  {
    category: 'admin_surface',
    label: 'Admin/login yuzalari',
    severity: 'LOW',
    build: site => `${site} (inurl:admin OR inurl:login OR inurl:dashboard OR inurl:panel OR inurl:administrator OR intitle:"admin")`,
  },
];

const OSINT_AUTO_CRON = process.env.OSINT_DORK_AUTO_CRON || '0 15 3 * * *';
const OSINT_AUTO_TIMEZONE = process.env.OSINT_DORK_TIMEZONE || 'Asia/Tashkent';
const DEFAULT_UZ_DOMAINS = ['.uz'];

@Injectable()
export class OsintDorkService {
  private readonly logger = new Logger(OsintDorkService.name);
  private autoScanRunning = false;
  private lastAutoScan:
    | { startedAt: string; finishedAt: string; status: string; saved: number; scannedDomains: number; error?: string }
    | null = null;

  constructor(private prisma: PrismaService) {}

  getConfig() {
    return {
      providerConfigured: this.providerConfigured(),
      provider: 'GOOGLE_CSE',
      scope: 'UZ_TLD',
      autoScan: {
        enabled: this.autoScanEnabled(),
        cron: OSINT_AUTO_CRON,
        timezone: OSINT_AUTO_TIMEZONE,
        limitPerQuery: this.autoScanLimitPerQuery(),
        maxDomainsPerScan: this.maxDomainsPerScan(),
        defaultDomains: this.defaultDomains(),
        running: this.autoScanRunning,
        last: this.lastAutoScan,
      },
      presets: DORK_PRESETS.map(({ category, label, severity }) => ({ category, label, severity })),
    };
  }

  @Cron(OSINT_AUTO_CRON, { timeZone: OSINT_AUTO_TIMEZONE })
  async runDailyUzDorkScan() {
    if (!this.autoScanEnabled()) return;
    if (this.autoScanRunning) {
      this.logger.warn('OSINT DORK auto scan skipped: previous scan is still running');
      return;
    }

    this.autoScanRunning = true;
    const startedAt = new Date();
    try {
      const result = await this.scan({
        limitPerQuery: this.autoScanLimitPerQuery(),
      });
      this.lastAutoScan = {
        startedAt: startedAt.toISOString(),
        finishedAt: new Date().toISOString(),
        status: result.providerConfigured ? 'DONE' : 'PROVIDER_NOT_CONFIGURED',
        saved: result.saved,
        scannedDomains: result.scannedDomains,
      };
      this.logger.log(
        `OSINT DORK auto scan ${this.lastAutoScan.status}: ${result.scannedDomains} .uz targets, ${result.saved} findings`,
      );
    } catch (e) {
      const message = e instanceof Error ? e.message : 'unknown error';
      this.lastAutoScan = {
        startedAt: startedAt.toISOString(),
        finishedAt: new Date().toISOString(),
        status: 'FAILED',
        saved: 0,
        scannedDomains: 0,
        error: message,
      };
      this.logger.error(`OSINT DORK auto scan failed: ${message}`);
    } finally {
      this.autoScanRunning = false;
    }
  }

  async listActive() {
    return this.prisma.osintDorkFinding.findMany({
      where: { dismissed: false, falsePositive: false },
      orderBy: [{ severity: 'desc' }, { foundAt: 'desc' }],
    });
  }

  async listFalsePositive() {
    return this.prisma.osintDorkFinding.findMany({
      where: { falsePositive: true },
      orderBy: { foundAt: 'desc' },
    });
  }

  async scan(input: ScanInput = {}) {
    const targets = await this.resolveTargets(input);
    const presets = this.resolvePresets(input.categories);
    const limit = this.clampLimit(input.limitPerQuery);
    const queries = targets.flatMap(target =>
      presets.map(preset => ({
        domain: target.domain,
        websiteId: target.websiteId,
        category: preset.category,
        severity: preset.severity,
        query: preset.build(`site:${target.domain}`),
      })),
    );

    if (!this.providerConfigured()) {
      return {
        providerConfigured: false,
        scannedDomains: targets.length,
        queries,
        saved: 0,
      };
    }

    let saved = 0;
    const errors: { domain: string; category: string; error: string }[] = [];

    for (const target of targets) {
      for (const preset of presets) {
        const query = preset.build(`site:${target.domain}`);
        try {
          const items = await this.search(query, limit);
          for (const item of items) {
            const url = (item.link || '').trim();
            if (!url || !this.resultBelongsToDomain(url, target.domain)) continue;
            const resultDomain = this.normalizeDomain(url);
            await this.saveFinding({
              domain: this.isTldTarget(target.domain) ? resultDomain : target.domain,
              websiteId: this.isTldTarget(target.domain) ? null : target.websiteId,
              url,
              title: item.title,
              category: preset.category,
              severity: preset.severity,
              query,
              evidence: item.snippet,
              source: 'GOOGLE_CSE',
              rawSignals: {
                displayLink: item.displayLink || null,
                provider: 'GOOGLE_CSE',
              },
            });
            saved++;
          }
        } catch (e) {
          errors.push({
            domain: target.domain,
            category: preset.category,
            error: e instanceof Error ? e.message : 'search failed',
          });
        }
      }
    }

    return {
      providerConfigured: true,
      scannedDomains: targets.length,
      queries,
      saved,
      errors,
    };
  }

  async createManual(input: ManualFindingInput) {
    if (!input?.url) throw new BadRequestException('url majburiy');
    const domain = this.normalizeDomain(input.domain || input.url);
    this.assertAllowedDomain(domain);

    return this.saveFinding({
      domain,
      url: input.url.trim(),
      title: input.title,
      category: input.category || 'manual_evidence',
      severity: input.severity || 'MEDIUM',
      query: input.query || 'manual',
      evidence: input.evidence,
      source: 'MANUAL',
      rawSignals: { provider: 'MANUAL' },
    });
  }

  async dismiss(id: string) {
    return this.prisma.osintDorkFinding.update({
      where: { id },
      data: { dismissed: true, status: 'DISMISSED' },
    });
  }

  async markFalsePositive(id: string) {
    return this.prisma.osintDorkFinding.update({
      where: { id },
      data: { dismissed: true, falsePositive: true, status: 'FALSE_POSITIVE' },
    });
  }

  async restore(id: string) {
    return this.prisma.osintDorkFinding.update({
      where: { id },
      data: { dismissed: false, falsePositive: false, status: 'OPEN' },
    });
  }

  private async resolveTargets(input: ScanInput) {
    const explicitTargets = !!(input.domains?.length || input.websiteIds?.length);
    const byId = input.websiteIds?.length
      ? await this.prisma.website.findMany({ where: { id: { in: input.websiteIds } }, select: { id: true, url: true } })
      : [];

    const manual = (input.domains || []).map(domain => ({ websiteId: null as string | null, domain: this.normalizeDomain(domain) }));
    const fromWebsites = byId.map(site => ({ websiteId: site.id, domain: this.normalizeDomain(site.url) }));

    let targets = [...manual, ...fromWebsites];
    if (!targets.length) {
      targets = this.defaultDomains().map(domain => ({
        websiteId: null as string | null,
        domain: this.normalizeDomain(domain),
      }));
    }

    const unique = new Map<string, { websiteId: string | null; domain: string }>();
    for (const target of targets) {
      if (!target.domain) continue;
      if (!this.isAllowedDomain(target.domain)) {
        if (explicitTargets) this.assertAllowedDomain(target.domain);
        continue;
      }
      if (!unique.has(target.domain)) unique.set(target.domain, target);
    }

    return Array.from(unique.values()).slice(0, this.maxDomainsPerScan());
  }

  private resolvePresets(categories?: string[]) {
    if (!categories?.length) return DORK_PRESETS;
    const allowed = new Set(categories);
    const presets = DORK_PRESETS.filter(preset => allowed.has(preset.category));
    if (!presets.length) throw new BadRequestException('Noto‘g‘ri OSINT kategoriya');
    return presets;
  }

  private clampLimit(value?: number) {
    const n = Number(value || 5);
    if (!Number.isFinite(n)) return 5;
    return Math.min(10, Math.max(1, Math.floor(n)));
  }

  private async search(query: string, limit: number): Promise<SearchItem[]> {
    const key = this.searchApiKey();
    const cx = this.searchCx();
    const res = await axios.get('https://www.googleapis.com/customsearch/v1', {
      params: { key, cx, q: query, num: limit },
      timeout: 15_000,
    });
    return Array.isArray(res.data?.items) ? res.data.items : [];
  }

  private async saveFinding(data: {
    domain: string;
    websiteId?: string | null;
    url: string;
    title?: string;
    category: string;
    severity: OsintSeverity;
    query: string;
    evidence?: string;
    source: string;
    rawSignals: Record<string, unknown>;
  }) {
    const title = this.redact(data.title || '');
    const evidence = this.redact(data.evidence || '');
    const sensitiveHits = Array.from(new Set([...title.hits, ...evidence.hits]));

    const existing = await this.prisma.osintDorkFinding.findUnique({
      where: { url_category: { url: data.url, category: data.category } },
    });

    const payload = {
      domain: data.domain,
      websiteId: data.websiteId || null,
      title: title.text || null,
      severity: data.severity,
      query: data.query,
      source: data.source,
      evidence: evidence.text || null,
      sensitiveHits,
      rawSignals: {
        ...data.rawSignals,
        redacted: true,
        hitCount: sensitiveHits.length,
      },
      foundAt: new Date(),
    };

    if (existing) {
      return this.prisma.osintDorkFinding.update({
        where: { id: existing.id },
        data: existing.falsePositive
          ? payload
          : { ...payload, dismissed: false, falsePositive: false, status: 'OPEN' },
      });
    }

    return this.prisma.osintDorkFinding.create({
      data: {
        ...payload,
        url: data.url,
        category: data.category,
        status: 'OPEN',
        dismissed: false,
        falsePositive: false,
      },
    });
  }

  private redact(value: string): { text: string; hits: string[] } {
    let text = String(value || '');
    const hits = new Set<string>();

    text = text.replace(/\b\d{14}\b/g, () => {
      hits.add('JSHSHIR_PINFL_VALUE');
      return '[REDACTED_JSHSHIR]';
    });
    text = text.replace(/\b[A-ZА-Я]{2}\s?\d{7}\b/gi, () => {
      hits.add('PASSPORT_VALUE');
      return '[REDACTED_PASSPORT]';
    });
    text = text.replace(/\b[\w.%+-]+@[\w.-]+\.[A-Z]{2,}\b/gi, () => {
      hits.add('EMAIL_VALUE');
      return '[REDACTED_EMAIL]';
    });
    text = text.replace(/\b(password|passwd|db_password|api[_-]?key|token|secret)\s*[:=]\s*["']?[^"'\s]+/gi, match => {
      hits.add('SECRET_VALUE');
      const key = match.split(/[:=]/)[0] || 'secret';
      return `${key}=[REDACTED_SECRET]`;
    });

    if (/\b(PINFL|JSHSHIR|ПИНФЛ|ЖШШИР)\b/i.test(text)) hits.add('JSHSHIR_PINFL_KEYWORD');
    if (/\b(passport|pasport|паспорт)\b/i.test(text)) hits.add('PASSPORT_KEYWORD');
    if (/\b(maxfiy|махфий|confidential|secret|служебного пользования)\b/i.test(text)) hits.add('CONFIDENTIAL_KEYWORD');

    return { text: text.slice(0, 2_000), hits: Array.from(hits) };
  }

  private providerConfigured() {
    return !!(this.searchApiKey() && this.searchCx());
  }

  private searchApiKey() {
    return process.env.GOOGLE_CSE_API_KEY || process.env.GOOGLE_API_KEY || '';
  }

  private searchCx() {
    return process.env.GOOGLE_CSE_ID || process.env.GOOGLE_CX || '';
  }

  private allowNonUz() {
    return process.env.OSINT_ALLOW_NON_UZ === 'true';
  }

  private autoScanEnabled() {
    return process.env.OSINT_DORK_AUTO_ENABLED !== 'false';
  }

  private autoScanLimitPerQuery() {
    const n = Number(process.env.OSINT_DORK_AUTO_LIMIT_PER_QUERY || 5);
    return Number.isFinite(n) ? n : 5;
  }

  private maxDomainsPerScan() {
    const n = Number(process.env.OSINT_DORK_MAX_DOMAINS_PER_SCAN || 300);
    return Number.isFinite(n) ? Math.max(1, Math.floor(n)) : 300;
  }

  private defaultDomains() {
    const base = process.env.OSINT_DORK_DEFAULT_DOMAINS
      ? process.env.OSINT_DORK_DEFAULT_DOMAINS.split(',')
      : DEFAULT_UZ_DOMAINS;
    const extra = (process.env.OSINT_DORK_EXTRA_DOMAINS || '').split(',');

    return [...base, ...extra]
      .map(domain => this.normalizeDomain(domain))
      .filter(Boolean)
      .filter((domain, index, list) => list.indexOf(domain) === index);
  }

  private assertAllowedDomain(domain: string) {
    if (this.isAllowedDomain(domain)) return;
    throw new BadRequestException(`OSINT dork faqat .uz domenlari uchun: ${domain}`);
  }

  private isAllowedDomain(domain: string) {
    if (this.allowNonUz()) return true;
    return this.isUzDomain(domain) || this.defaultDomains().includes(domain);
  }

  private resultBelongsToDomain(url: string, domain: string) {
    const host = this.normalizeDomain(url);
    if (this.isTldTarget(domain)) return host.endsWith(domain);
    return host === domain || host.endsWith(`.${domain}`);
  }

  private isUzDomain(domain: string) {
    return domain === '.uz' || domain.endsWith('.uz');
  }

  private isTldTarget(domain: string) {
    return domain.startsWith('.');
  }

  private normalizeDomain(value: string) {
    const raw = String(value || '').trim().toLowerCase();
    if (!raw) return '';
    try {
      const url = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
      return url.hostname.replace(/^www\./, '');
    } catch {
      return raw.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].replace(/^www\./, '');
    }
  }
}
