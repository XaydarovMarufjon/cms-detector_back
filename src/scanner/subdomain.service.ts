// src/scanner/subdomain.service.ts
import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { promises as dns } from 'dns';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export interface SubdomainResult {
    subdomain: string;
    alive: boolean;
    source: string[];
    statusCode?: number;
    title?: string;
}

@Injectable()
export class SubdomainService {
    private readonly logger = new Logger(SubdomainService.name);

    async discover(domain: string): Promise<SubdomainResult[]> {
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
        return results.sort((a, b) => {
            if (a.alive !== b.alive) return a.alive ? -1 : 1;
            return a.subdomain.localeCompare(b.subdomain);
        });
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

    // ── httpx-based host probe (alive + statusCode + title) ──────────────────
    private async probeHost(hostname: string): Promise<{ alive: boolean; statusCode?: number; title?: string }> {
        // Try httpx first (more accurate)
        const httpxResult = await this.probeWithHttpx(hostname);
        if (httpxResult !== null) return httpxResult;

        // Fallback: DNS + axios HEAD
        try {
            await dns.resolve(hostname);
        } catch {
            return { alive: false };
        }

        for (const scheme of ['https', 'http']) {
            try {
                const res = await axios.head(`${scheme}://${hostname}`, {
                    timeout: 8000,
                    maxRedirects: 5,
                    validateStatus: () => true,
                    headers: { 'User-Agent': 'cms-radar/1.0' },
                });
                return { alive: true, statusCode: res.status };
            } catch {
                // try next scheme
            }
        }

        return { alive: false };
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
                    ['-u', hostname, '-silent', '-status-code', '-title', '-json', '-timeout', '8'],
                    { timeout: 15_000 },
                );
                const line = stdout.trim().split('\n')[0];
                if (!line) return { alive: false };
                const parsed = JSON.parse(line);
                return {
                    alive: true,
                    statusCode: parsed['status-code'] ?? parsed.status_code,
                    title: parsed.title,
                };
            } catch (err: any) {
                if (err?.code === 'ENOENT') continue;
                // httpx found but failed = host is dead or error
                return { alive: false };
            }
        }
        return null; // httpx not found, fall back to axios
    }
}
