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
}

@Injectable()
export class SubdomainService {
    private readonly logger = new Logger(SubdomainService.name);

    async discover(domain: string): Promise<SubdomainResult[]> {
        // Passive sources run in parallel; neither blocks the other
        const [crtShResult, subfinderResult] = await Promise.allSettled([
            this.fromCrtSh(domain),
            this.fromSubfinder(domain),
        ]);

        // Merge into a map: subdomain → set of sources
        const sourceMap = new Map<string, Set<string>>();

        const merge = (list: string[], tag: string) => {
            for (const raw of list) {
                const sub = raw.toLowerCase().replace(/^\*\./, '').trim();
                // Must be a real subdomain of the target domain, not the domain itself
                if (!sub || sub === domain || !sub.endsWith(`.${domain}`)) continue;
                if (!sourceMap.has(sub)) sourceMap.set(sub, new Set());
                sourceMap.get(sub)!.add(tag);
            }
        };

        if (crtShResult.status === 'fulfilled')   merge(crtShResult.value,   'crt.sh');
        if (subfinderResult.status === 'fulfilled') merge(subfinderResult.value, 'subfinder');

        if (!sourceMap.size) return [];

        // DNS alive check — run all in parallel with concurrency cap
        const entries = [...sourceMap.entries()];
        const BATCH = 50;
        const resolved: SubdomainResult[] = [];

        for (let i = 0; i < entries.length; i += BATCH) {
            const batch = entries.slice(i, i + BATCH);
            const checks = await Promise.allSettled(
                batch.map(async ([sub, srcs]) => ({
                    subdomain: sub,
                    alive: await this.isAlive(sub),
                    source: [...srcs],
                })),
            );
            for (const r of checks) {
                if (r.status === 'fulfilled' && r.value.alive) {
                    resolved.push(r.value);
                }
            }
        }

        return resolved.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
    }

    // ── crt.sh certificate transparency log ──────────────────────────────────
    private async fromCrtSh(domain: string): Promise<string[]> {
        try {
            const { data } = await axios.get<Array<{ name_value: string }>>(
                `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
                { timeout: 20000, headers: { 'User-Agent': 'cms-radar/1.0' } },
            );
            return data.flatMap(e => e.name_value.split('\n'));
        } catch (err) {
            this.logger.warn(`crt.sh lookup failed for ${domain}: ${String(err)}`);
            return [];
        }
    }

    // ── subfinder (optional — skipped silently if not installed) ─────────────
    private async fromSubfinder(domain: string): Promise<string[]> {
        // Look for subfinder in common install locations
        const candidates = [
            'subfinder',
            `${process.env['HOME']}/.local/bin/subfinder`,
            '/usr/local/bin/subfinder',
            '/usr/bin/subfinder',
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
                // ENOENT = binary not found at this path → try next
                if (err?.code !== 'ENOENT') {
                    this.logger.warn(`subfinder failed for ${domain}: ${String(err)}`);
                    return [];
                }
            }
        }
        return [];   // subfinder not found anywhere
    }

    // ── Web server check: DNS + HTTP/HTTPS response ───────────────────────────
    // DNS resolve is cheap — use it as a fast pre-filter before HTTP probing
    private async isAlive(hostname: string): Promise<boolean> {
        // 1. DNS must resolve first (quick reject for non-existent hosts)
        try {
            await dns.resolve(hostname);
        } catch {
            return false;
        }

        // 2. Must respond to HTTP or HTTPS (any status code = web server exists)
        for (const scheme of ['https', 'http']) {
            try {
                await axios.head(`${scheme}://${hostname}`, {
                    timeout: 8000,
                    maxRedirects: 5,
                    validateStatus: () => true,   // any status → web server is up
                    headers: { 'User-Agent': 'cms-radar/1.0' },
                });
                return true;
            } catch {
                // connection refused, timeout, SSL error → try next scheme
            }
        }

        return false;  // DNS ok but no web server on 80/443
    }
}
