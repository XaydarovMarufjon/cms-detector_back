// src/scanner/subdomain.service.ts
import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { execFile } from 'child_process';
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
export class SubdomainService {
    private readonly logger = new Logger(SubdomainService.name);

    constructor(private readonly prisma: PrismaService) {}

    async getCachedAlive(domain: string): Promise<SubdomainResult[]> {
        const normalized = this.normalizeDomain(domain);
        if (!normalized) return [];

        const rows = await this.prisma.subdomainCache.findMany({
            where: { domain: normalized },
            orderBy: { subdomain: 'asc' },
        });

        return rows.map(row => ({
            subdomain: row.subdomain,
            alive: true,
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

        const [crtShResult, subfinderResult] = await Promise.allSettled([
            this.fromCrtSh(domain),
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

        if (crtShResult.status === 'fulfilled')    merge(crtShResult.value,    'crt.sh');
        if (subfinderResult.status === 'fulfilled') merge(subfinderResult.value, 'subfinder');

        if (!sourceMap.size) return [];

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

    private async saveAlive(domain: string, results: SubdomainResult[], websiteId?: string) {
        const alive = results.filter(r => r.alive);

        try {
            await this.prisma.$transaction([
                this.prisma.subdomainCache.deleteMany({ where: { domain } }),
                ...(alive.length
                    ? [this.prisma.subdomainCache.createMany({
                        data: alive.map(r => ({
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
            return new URL(url).hostname.replace(/^www\./, '');
        } catch {
            return raw
                .replace(/^https?:\/\//, '')
                .split('/')[0]
                .replace(/^www\./, '');
        }
    }

    // ── crt.sh certificate transparency log ──────────────────────────────────
    private async fromCrtSh(domain: string): Promise<string[]> {
        try {
            const { data } = await axios.get<Array<{ name_value: string }>>(
                `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
                {
                    timeout: 30000,
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
