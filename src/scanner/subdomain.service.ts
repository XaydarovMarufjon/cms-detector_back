// src/scanner/subdomain.service.ts
import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import axios from 'axios';
import { execFile } from 'child_process';
import { CronJob } from 'cron';
import { promisify } from 'util';
import { PrismaService } from '../prisma/prisma.service';

const execFileAsync = promisify(execFile);

export interface SubdomainResult {
    subdomain: string;
    alive: boolean;
    source: string[];
    statusCode?: number;
    title?: string;
    cached?: boolean;
    discoveredAt?: Date;
}

@Injectable()
export class SubdomainService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger(SubdomainService.name);
    private readonly autoScanEnabled = process.env.SUBDOMAIN_AUTO_SCAN_AUTO !== 'false';
    private readonly autoScanDays = Math.max(1, Number(process.env.SUBDOMAIN_AUTO_SCAN_DAYS || 10));
    private readonly autoScanCron = process.env.SUBDOMAIN_AUTO_SCAN_CRON || '0 30 4 * * *';
    private readonly autoScanBatch = Math.max(1, Number(process.env.SUBDOMAIN_AUTO_SCAN_BATCH || 200));
    private autoScanJob: CronJob | null = null;
    private startupTimer: NodeJS.Timeout | null = null;
    private autoScanRunning = false;
    private queuedWebsiteIds = new Set<string>();
    private discoveryQueue: Promise<void> = Promise.resolve();
    private discoveryPromises = new Map<string, Promise<SubdomainResult[]>>();

    constructor(private readonly prisma: PrismaService) {}

    onModuleInit() {
        if (!this.autoScanEnabled) return;

        this.autoScanJob = new CronJob(this.autoScanCron, () => {
            this.runDueWebsiteScans('schedule').catch(err => {
                this.logger.error(`Subdomain auto scan failed: ${String(err)}`);
            });
        });
        this.autoScanJob.start();
        this.startupTimer = setTimeout(() => {
            this.runDueWebsiteScans('startup').catch(err => {
                this.logger.error(`Subdomain startup scan failed: ${String(err)}`);
            });
        }, 5000);

        this.logger.log(`Subdomain auto scan enabled: every ${this.autoScanDays} day(s), cron=${this.autoScanCron}`);
    }

    onModuleDestroy() {
        this.autoScanJob?.stop();
        if (this.startupTimer) clearTimeout(this.startupTimer);
    }

    async getCachedAlive(domain: string): Promise<SubdomainResult[]> {
        const normalized = this.normalizeDomain(domain);
        if (!normalized) return [];

        const rows = await this.prisma.subdomainCache.findMany({
            where: { domain: normalized },
            orderBy: { subdomain: 'asc' },
        });

        return rows.map(row => ({
            subdomain: row.subdomain,
            alive: row.statusCode !== null,
            source: row.source,
            statusCode: row.statusCode ?? undefined,
            title: row.title ?? undefined,
            cached: true,
            discoveredAt: row.discoveredAt,
        }));
    }

    async discover(domain: string, websiteId?: string): Promise<SubdomainResult[]> {
        domain = this.normalizeDomain(domain);
        if (!domain) return [];

        const results = await this.enqueueDiscovery(domain, () => this.discoverNow(domain, websiteId));
        if (websiteId) await this.markScanCompleted(websiteId);
        return results;
    }

    private enqueueDiscovery(domain: string, task: () => Promise<SubdomainResult[]>): Promise<SubdomainResult[]> {
        const existing = this.discoveryPromises.get(domain);
        if (existing) return existing;

        const queued = this.discoveryQueue
            .then(async () => {
                this.logger.log(`Subdomain queue started: ${domain}`);
                const startedAt = Date.now();
                const results = await task();
                this.logger.log(`Subdomain queue finished: ${domain}, ${results.length} result(s), ${Date.now() - startedAt}ms`);
                return results;
            })
            .finally(() => {
                this.discoveryPromises.delete(domain);
            });

        this.discoveryPromises.set(domain, queued);
        this.discoveryQueue = queued.then(() => undefined, () => undefined);
        return queued;
    }

    private async discoverNow(domain: string, websiteId?: string): Promise<SubdomainResult[]> {
        const [
            crtShResult,
            certSpotterResult,
            hackerTargetResult,
            rapidDnsResult,
            subfinderResult,
        ] = await Promise.allSettled([
            this.fromCrtSh(domain),
            this.fromCertSpotter(domain),
            this.fromHackerTarget(domain),
            this.fromRapidDns(domain),
            this.fromSubfinder(domain),
        ]);

        const sourceMap = new Map<string, Set<string>>();

        const merge = (list: string[], tag: string) => {
            for (const raw of list) {
                const sub = raw.toLowerCase().replace(/^\*\./, '').trim();
                if (!sub || sub === domain || !sub.endsWith(`.${domain}`)) continue;
                if (!sourceMap.has(sub)) sourceMap.set(sub, new Set());
                sourceMap.get(sub)!.add(tag);
            }
        };

        if (crtShResult.status === 'fulfilled')         merge(crtShResult.value,         'crt.sh');
        if (certSpotterResult.status === 'fulfilled')   merge(certSpotterResult.value,   'certspotter');
        if (hackerTargetResult.status === 'fulfilled')  merge(hackerTargetResult.value,  'hackertarget');
        if (rapidDnsResult.status === 'fulfilled')      merge(rapidDnsResult.value,      'rapiddns');
        if (subfinderResult.status === 'fulfilled')     merge(subfinderResult.value,     'subfinder');

        if (!sourceMap.size) {
            return [];
        }

        // Check alive status — keep ALL results, just mark alive/dead
        const entries = [...sourceMap.entries()];
        const BATCH = 50;
        const results: SubdomainResult[] = [];

        for (let i = 0; i < entries.length; i += BATCH) {
            const batch = entries.slice(i, i + BATCH);
            const checks = await Promise.allSettled(
                batch.map(async ([sub, srcs]) => {
                    const probe = await this.probeHost(sub);
                    return {
                        subdomain: sub,
                        alive: probe.alive,
                        source: [...srcs],
                        statusCode: probe.statusCode,
                        title: probe.title,
                    };
                }),
            );
            for (const r of checks) {
                if (r.status === 'fulfilled') results.push(r.value);
            }
        }

        // Alive first, then dead — alphabetical within each group
        const sorted = results.sort((a, b) => {
            if (a.alive !== b.alive) return a.alive ? -1 : 1;
            return a.subdomain.localeCompare(b.subdomain);
        });

        await this.saveAlive(domain, sorted, websiteId);
        return sorted;
    }

    queueWebsiteDiscovery(website: { id: string; url: string; label?: string | null }, reason = 'queued') {
        const domain = this.normalizeDomain(website.url);
        if (!domain || this.queuedWebsiteIds.has(website.id)) return;

        this.queuedWebsiteIds.add(website.id);
        void this.discover(domain, website.id)
            .then(results => {
                this.logger.log(`Subdomain ${reason} scan done for ${domain}: ${results.length} result(s)`);
            })
            .catch(err => {
                this.logger.warn(`Subdomain ${reason} scan failed for ${domain}: ${String(err)}`);
            })
            .finally(() => {
                this.queuedWebsiteIds.delete(website.id);
            });
    }

    async runDueWebsiteScans(source: 'startup' | 'schedule' | 'manual' = 'manual') {
        if (this.autoScanRunning) return { running: true, scanned: 0, due: 0 };
        this.autoScanRunning = true;

        const cutoff = new Date(Date.now() - this.autoScanDays * 24 * 60 * 60 * 1000);
        try {
            const due = await this.prisma.website.findMany({
                where: {
                    OR: [
                        { subdomainsScannedAt: null },
                        { subdomainsScannedAt: { lte: cutoff } },
                    ],
                },
                orderBy: [
                    { subdomainsScannedAt: 'asc' },
                    { createdAt: 'asc' },
                ],
                take: this.autoScanBatch,
            });

            if (!due.length) return { running: false, scanned: 0, due: 0 };

            const grouped = new Map<string, { website: typeof due[number]; ids: string[] }>();
            for (const website of due) {
                const domain = this.normalizeDomain(website.url);
                if (!domain) continue;

                const current = grouped.get(domain);
                if (current) current.ids.push(website.id);
                else grouped.set(domain, { website, ids: [website.id] });
            }

            this.logger.log(`Subdomain ${source} scan: ${due.length} due website(s), ${grouped.size} root domain(s)`);
            let scanned = 0;
            for (const [domain, group] of grouped) {
                try {
                    const results = await this.discover(domain, group.website.id);
                    await this.markScanCompletedMany(group.ids);
                    scanned += 1;
                    this.logger.log(`Subdomain auto scan done for ${domain}: ${results.length} result(s)`);
                } catch (err) {
                    this.logger.warn(`Subdomain auto scan failed for ${domain}: ${String(err)}`);
                }
            }

            return { running: false, scanned, due: due.length };
        } finally {
            this.autoScanRunning = false;
        }
    }

    private async markScanCompletedMany(websiteIds: string[]) {
        if (!websiteIds.length) return;
        try {
            await this.prisma.website.updateMany({
                where: { id: { in: websiteIds } },
                data: { subdomainsScannedAt: new Date() },
            });
        } catch (err) {
            this.logger.warn(`subdomain scan completion save failed for group: ${String(err)}`);
        }
    }

    private async markScanCompleted(websiteId?: string) {
        if (!websiteId) return;
        try {
            await this.prisma.website.update({
                where: { id: websiteId },
                data: { subdomainsScannedAt: new Date() },
            });
        } catch (err) {
            this.logger.warn(`subdomain scan completion save failed for ${websiteId}: ${String(err)}`);
        }
    }

    private async saveAlive(domain: string, results: SubdomainResult[], websiteId?: string) {
        try {
            await this.prisma.$transaction([
                this.prisma.subdomainCache.deleteMany({ where: { domain } }),
                ...(results.length
                    ? [this.prisma.subdomainCache.createMany({
                        data: results.map(r => ({
                            websiteId,
                            domain,
                            subdomain: r.subdomain,
                            source: r.source,
                            statusCode: r.statusCode,
                            title: r.title,
                        })),
                    })]
                    : []),
            ]);
        } catch (err) {
            this.logger.warn(`subdomain cache save failed for ${domain}: ${String(err)}`);
        }
    }

    private normalizeDomain(input: string): string {
        const raw = (input || '').trim().toLowerCase();
        if (!raw) return '';
        try {
            const url = raw.startsWith('http') ? raw : `https://${raw}`;
            return this.extractRootDomain(new URL(url).hostname);
        } catch {
            const host = raw
                .replace(/^https?:\/\//, '')
                .split('/')[0]
                .replace(/^www\./, '');
            return this.extractRootDomain(host);
        }
    }

    private extractRootDomain(hostname: string): string {
        const host = hostname.toLowerCase().replace(/^www\./, '');
        const parts = host.split('.').filter(Boolean);
        return parts.length > 2 ? parts.slice(-2).join('.') : host;
    }

    // ── passive subdomain sources ────────────────────────────────────────────
    private async fromCrtSh(domain: string): Promise<string[]> {
        try {
            const { data } = await axios.get<Array<{ name_value: string }>>(
                `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
                {
                    timeout: 12_000,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (compatible; cms-radar/1.0)',
                        'Accept': 'application/json',
                    },
                },
            );
            if (!Array.isArray(data)) return [];
            return data.flatMap(e => (e.name_value ?? '').split('\n'));
        } catch (err) {
            this.logger.warn(`crt.sh lookup failed for ${domain}: ${String(err)}`);
            return [];
        }
    }

    private async fromCertSpotter(domain: string): Promise<string[]> {
        try {
            const { data } = await axios.get<Array<{ dns_names?: string[] }>>(
                `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
                {
                    timeout: 10_000,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (compatible; cms-radar/1.0)',
                        'Accept': 'application/json',
                    },
                },
            );
            if (!Array.isArray(data)) return [];
            return data.flatMap(row => row.dns_names ?? []);
        } catch (err) {
            this.logger.warn(`certspotter lookup failed for ${domain}: ${String(err)}`);
            return [];
        }
    }

    private async fromHackerTarget(domain: string): Promise<string[]> {
        try {
            const { data } = await axios.get<string>(
                `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
                {
                    timeout: 10_000,
                    responseType: 'text',
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (compatible; cms-radar/1.0)',
                        'Accept': 'text/plain,*/*',
                    },
                },
            );
            return String(data)
                .split(/\r?\n/)
                .map(line => line.split(',')[0]?.trim())
                .filter(Boolean);
        } catch (err) {
            this.logger.warn(`hackertarget lookup failed for ${domain}: ${String(err)}`);
            return [];
        }
    }

    private async fromRapidDns(domain: string): Promise<string[]> {
        try {
            const { data } = await axios.get<string>(
                `https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`,
                {
                    timeout: 12_000,
                    responseType: 'text',
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (compatible; cms-radar/1.0)',
                        'Accept': 'text/html,*/*',
                    },
                },
            );
            const found = new Set<string>();
            const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const pattern = new RegExp(`(?:[a-z0-9_-]+\\.)+${escaped}`, 'gi');
            for (const match of String(data).matchAll(pattern)) {
                found.add(match[0].toLowerCase());
            }
            return [...found];
        } catch (err) {
            this.logger.warn(`rapiddns lookup failed for ${domain}: ${String(err)}`);
            return [];
        }
    }

    // ── subfinder ─────────────────────────────────────────────────────────────
    private async fromSubfinder(domain: string): Promise<string[]> {
        const candidates = [
            'subfinder',
            '/opt/homebrew/bin/subfinder',
            '/usr/local/bin/subfinder',
            '/usr/bin/subfinder',
            `${process.env['HOME']}/.local/bin/subfinder`,
            `${process.env['HOME']}/go/bin/subfinder`,
        ];

        for (const bin of candidates) {
            try {
                const { stdout } = await execFileAsync(
                    bin,
                    ['-d', domain, '-silent', '-all'],
                    { timeout: 60_000 },
                );
                return stdout.split('\n').filter(Boolean);
            } catch (err: any) {
                if (err?.code !== 'ENOENT') {
                    this.logger.warn(`subfinder failed for ${domain}: ${String(err)}`);
                    return [];
                }
            }
        }
        return [];
    }

    // ── host probe (alive + statusCode + title) ──────────────────────────────
    private async probeHost(hostname: string): Promise<{ alive: boolean; statusCode?: number; title?: string }> {
        // Try ProjectDiscovery httpx first. If it cannot resolve/probe a host,
        // fall back to axios instead of marking the host dead immediately.
        const httpxResult = await this.probeWithHttpx(hostname);
        if (httpxResult?.alive) return httpxResult;

        return this.probeWithAxios(hostname);
    }

    private async probeWithHttpx(hostname: string): Promise<{ alive: boolean; statusCode?: number; title?: string } | null> {
        const candidates = [
            'httpx',
            '/opt/homebrew/bin/httpx',
            '/usr/local/bin/httpx',
            `${process.env['HOME']}/go/bin/httpx`,
        ];

        for (const bin of candidates) {
            try {
                const { stdout } = await execFileAsync(
                    bin,
                    ['-u', hostname, '-silent', '-probe', '-status-code', '-title', '-json', '-timeout', '8'],
                    { timeout: 15_000 },
                );
                const line = stdout
                    .split('\n')
                    .map(l => l.trim())
                    .find(l => l.startsWith('{'));
                if (!line) return null;
                const parsed = JSON.parse(line);
                if (parsed.failed || parsed.error) return null;
                const statusCode = parsed['status-code'] ?? parsed.status_code;
                return {
                    alive: statusCode ? statusCode > 0 : true,
                    statusCode,
                    title: parsed.title,
                };
            } catch (err: any) {
                if (err?.code === 'ENOENT') continue;
                this.logger.debug?.(`httpx probe failed for ${hostname}: ${String(err?.message || err)}`);
                return null;
            }
        }
        return null; // httpx not found, fall back to axios
    }

    private async probeWithAxios(hostname: string): Promise<{ alive: boolean; statusCode?: number; title?: string }> {
        for (const scheme of ['https', 'http']) {
            const url = `${scheme}://${hostname}`;
            const head = await this.request(url, 'HEAD');
            if (head) return head;

            const get = await this.request(url, 'GET');
            if (get) return get;
        }
        return { alive: false };
    }

    private async request(
        url: string,
        method: 'HEAD' | 'GET',
    ): Promise<{ alive: boolean; statusCode?: number; title?: string } | null> {
        try {
            const res = await axios.request<string>({
                url,
                method,
                timeout: 10_000,
                maxRedirects: 5,
                maxContentLength: 512 * 1024,
                responseType: 'text',
                validateStatus: () => true,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; cms-radar/1.0)',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                },
            });

            return {
                alive: true,
                statusCode: res.status,
                title: method === 'GET' && typeof res.data === 'string'
                    ? this.extractTitle(res.data)
                    : undefined,
            };
        } catch {
            return null;
        }
    }

    private extractTitle(html: string): string | undefined {
        const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
        if (!match) return undefined;
        return match[1].replace(/\s+/g, ' ').trim().slice(0, 120) || undefined;
    }
}
