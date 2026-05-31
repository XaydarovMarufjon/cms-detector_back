import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import axios, { AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import * as http from 'http';
import * as https from 'https';
import { createHash } from 'crypto';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import {
    JS_BUNDLE_FINGERPRINTS,
    STRONG_PATTERN_ONLY_TECHS,
    SUPPLEMENTAL_CMS_FILE_PROBES,
    WAPPALYZER_STYLE_FINGERPRINTS,
    WappalyzerStylePattern,
} from './cms-fingerprints';

interface ProxySourceStatus {
  url:        string;
  protocol:   string;
  ok:         boolean;
  count:      number;
  error?:     string;
  fetchedAt:  string;
}

interface ProxySourceConfig {
    protocol: string;
    url: string;
}

const DEFAULT_PROXY_SOURCES: ProxySourceConfig[] = [
    { protocol: 'http', url: 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt' },
    { protocol: 'socks4', url: 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt' },
    { protocol: 'socks5', url: 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt' },
    { protocol: 'http', url: 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt' },
    { protocol: 'socks4', url: 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt' },
    { protocol: 'socks5', url: 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt' },
    { protocol: 'http', url: 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt' },
    { protocol: 'socks4', url: 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt' },
    { protocol: 'socks5', url: 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt' },
];

export type SiteCategory =
  | 'CMS'
  | 'E-commerce CMS'
  | 'Backend Framework'
  | 'Frontend Framework / SPA'
  | 'Fullstack Framework'
  | 'Static Website'
  | 'Static Site Generator (SSG)'
  | 'Jamstack'
  | 'Headless CMS'
  | 'Server-Side Rendered (SSR)'
  | 'Progressive Web App (PWA)'
  | 'Web Builder / No-Code Platform'
  | 'Forum Engine'
  | 'Wiki Engine'
  | 'Blog Engine'
  | 'Learning Management System (LMS)'
  | 'CRM / ERP Web System'
  | 'Custom / Proprietary System'
  | 'API-only Backend'
  | 'Unknown';

export interface CmsDetectionResult {
    url: string;
    cms: string | null;
    version: string | null;
    versionSource: string | null;
    category: SiteCategory;
    confidence: number;
    detectionMethod: string[];
    evidence: DetectionEvidence[];
    detectedAt: Date;
    rawSignals: Record<string, string>;
    serverTech: string[];
    jsFrameworks: string[];
    httpStatus: number | null;
    pageTitle: string | null;
}

export interface CmsDetectOptions {
    mode?: 'FAST' | 'FULL';
    timeoutMs?: number;
}

interface TechSignal {
    name: string;
    version: string | null;
    category: SiteCategory;
    confidence: number;
    method: string;
    source?: string;
}

export type EvidenceType =
  | 'file'
  | 'meta'
  | 'cookie'
  | 'inline'
  | 'header'
  | 'asset'
  | 'crawl'
  | 'comment'
  | 'bundle'
  | 'pattern'
  | 'other';

export interface DetectionEvidence {
    name: string;
    method: string;
    type: EvidenceType;
    confidence: number;
    version: string | null;
    source: string | null;
}

@Injectable()
export class CmsDetectorService implements OnModuleInit {
    private readonly logger = new Logger(CmsDetectorService.name);

    private proxies: string[] = this.getManualProxies();
    private proxyIndex = 0;

    // Auto-refresh state
    private readonly refreshMinutes = Math.max(5, Number(process.env['PROXY_REFRESH_MINUTES'] || 360));
    private readonly maxProxies     = Math.max(10, Number(process.env['PROXY_MAX'] || 200));
    private readonly configuredSources = (process.env['PROXY_SOURCES'] || '')
        .split(',').map(s => s.trim()).filter(Boolean)
        .map(spec => {
            const [proto, url] = spec.split('|');
            return { protocol: (proto || 'http').toLowerCase(), url: (url || '').trim() };
        })
        .filter(s => s.url);
    private readonly usingDefaultProxySources = this.configuredSources.length === 0;
    private readonly sources = this.usingDefaultProxySources ? DEFAULT_PROXY_SOURCES : this.configuredSources;
    private readonly validationCandidateLimit = Math.max(
        this.maxProxies,
        Number(process.env['PROXY_VALIDATION_CANDIDATES'] || Math.min(this.maxProxies * 2, 180)),
    );
    private readonly validationTarget = Math.max(1, Math.min(
        this.maxProxies,
        Number(process.env['PROXY_VALIDATION_TARGET'] || 50),
    ));
    private readonly validationConcurrency = Math.max(5, Number(process.env['PROXY_VALIDATION_CONCURRENCY'] || 80));
    private readonly validationTimeoutMs = Math.max(1000, Number(process.env['PROXY_VALIDATION_TIMEOUT_MS'] || 2000));
    private readonly proxyFetchTimeoutMs = Math.max(1000, Number(process.env['PROXY_FETCH_TIMEOUT_MS'] || 3500));
    private lastRefresh: string | null = null;
    private refreshing = false;
    private sourceStatus: ProxySourceStatus[] = [];
    private refreshTimer: NodeJS.Timeout | null = null;
    private autoRefreshEnabled = false;  // set in onModuleInit based on sources

    // Proxy health tracker — free proxies: aggressive
    private readonly PROXY_DEAD_AFTER = 1;            // 1 fail → dead (free proxies rarely revive)
    private readonly PROXY_REVIVE_MS  = 30 * 60_000;  // try again after 30 min
    private proxyHealth = new Map<string, { fails: number; deadUntil: number; lastOk: number }>();

    // Per-domain backoff (429/403)
    private readonly DOMAIN_COOLDOWN_MS = 60_000;     // 60s cooldown
    private domainCooldown = new Map<string, number>();

    private readonly httpAgent  = new http.Agent({  keepAlive: true, maxSockets: 50, maxFreeSockets: 10, timeout: 25_000 });
    private readonly httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 50, maxFreeSockets: 10, timeout: 25_000, rejectUnauthorized: false });

    private readonly detectCache = new Map<string, { result: CmsDetectionResult; exp: number }>();
    private readonly DETECT_TTL = 30 * 60 * 1000; // 30 min

    private getNextAgent(): { agent: any; proxyUrl: string } | { agent: undefined; proxyUrl: null } {
        if (!this.proxies.length) return { agent: undefined, proxyUrl: null };
        const now = Date.now();
        // Try up to N times to find a healthy proxy (N = proxies.length)
        for (let i = 0; i < this.proxies.length; i++) {
            const proxy = this.proxies[this.proxyIndex % this.proxies.length];
            this.proxyIndex++;
            const h = this.proxyHealth.get(proxy);
            if (h && h.deadUntil > now) continue;  // skip dead proxy
            const agent = this.createProxyAgent(proxy);
            return { agent, proxyUrl: proxy };
        }
        // All dead — fall back to direct (own IP) rather than fail
        return { agent: undefined, proxyUrl: null };
    }

    private reportProxyResult(proxyUrl: string | null, ok: boolean) {
        if (!proxyUrl) return;
        const h = this.proxyHealth.get(proxyUrl) || { fails: 0, deadUntil: 0, lastOk: 0 };
        if (ok) {
            h.fails = 0;
            h.lastOk = Date.now();
            h.deadUntil = 0;
        } else {
            h.fails++;
            if (h.fails >= this.PROXY_DEAD_AFTER) {
                h.deadUntil = Date.now() + this.PROXY_REVIVE_MS;
            }
        }
        this.proxyHealth.set(proxyUrl, h);
    }

    private getDomainCooldown(url: string): number {
        try {
            const host = new URL(url).hostname;
            const until = this.domainCooldown.get(host);
            return until && until > Date.now() ? until : 0;
        } catch { return 0; }
    }

    private setDomainCooldown(url: string) {
        try {
            const host = new URL(url).hostname;
            this.domainCooldown.set(host, Date.now() + this.DOMAIN_COOLDOWN_MS);
        } catch { /* ignore */ }
    }

    async onModuleInit() {
        if (this.sources.length) {
            this.autoRefreshEnabled = true;
            this.startAutoRefresh();
        }
    }

    private startAutoRefresh() {
        if (this.refreshTimer) return;
        const sourceMode = this.usingDefaultProxySources ? 'default' : 'env';
        this.logger.log(`Proxy auto-refresh: ${this.sources.length} ${sourceMode} source(s), every ${this.refreshMinutes} min`);
        this.refreshProxies().catch(e => this.logger.error(`Initial proxy refresh failed: ${e?.message}`));
        this.refreshTimer = setInterval(
            () => this.refreshProxies().catch(e => this.logger.error(`Proxy refresh failed: ${e?.message}`)),
            this.refreshMinutes * 60_000,
        );
    }

    private stopAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }

    setAutoRefreshEnabled(enabled: boolean): { enabled: boolean } {
        if (enabled === this.autoRefreshEnabled) return { enabled };
        this.autoRefreshEnabled = enabled;
        if (enabled) {
            this.startAutoRefresh();
        } else {
            this.stopAutoRefresh();
            // Wipe so getNextAgent() returns undefined → axios uses default agent → own IP
            this.proxies = this.getManualProxies();
            this.proxyIndex = 0;
            this.sourceStatus = [];
            this.lastRefresh = null;
            this.logger.log('Avto-yangilash o\'chirildi — faqat PROXY_LIST yoki o\'z IP orqali ishlaydi');
        }
        return { enabled };
    }

    async refreshProxies(): Promise<{ total: number; sources: ProxySourceStatus[] }> {
        if (this.refreshing) return { total: this.proxies.length, sources: this.sourceStatus };
        this.refreshing = true;
        try {
            const manual = this.getManualProxies();
            const collected = new Set<string>(manual);
            const statuses: ProxySourceStatus[] = [];
            const perSourceQuota = Math.max(30, Math.ceil(this.validationCandidateLimit / Math.max(this.sources.length, 1)));
            let capReached = false;
            for (const src of this.sources) {
                const status: ProxySourceStatus = {
                    url: src.url, protocol: src.protocol,
                    ok: false, count: 0, fetchedAt: new Date().toISOString(),
                };
                if (capReached) {
                    status.error = `oraliq cheklov (${this.maxProxies}) to'ldi`;
                    statuses.push(status);
                    continue;
                }
                try {
                    const resp = await axios.get<string>(src.url, {
                        timeout: 15_000,
                        responseType: 'text',
                        transformResponse: [(d) => d],
                        validateStatus: s => s >= 200 && s < 300,
                    });
                    const body = typeof resp.data === 'string' ? resp.data : String(resp.data);
                    const lines = body.split(/\r?\n/);
                    let added = 0;
                    for (const ln of lines) {
                        const t = ln.trim();
                        if (!t) continue;
                        const normalized = this.normalizeProxyLine(t, src.protocol);
                        if (normalized && !collected.has(normalized)) {
                            collected.add(normalized);
                            added++;
                            if (added >= perSourceQuota) break;
                            if (collected.size >= this.validationCandidateLimit) break;
                        }
                    }
                    status.ok = true;
                    status.count = added;
                } catch (e: any) {
                    status.ok = false;
                    status.error = e?.message || 'fetch failed';
                }
                statuses.push(status);
                if (collected.size >= this.validationCandidateLimit) capReached = true;
            }
            const list = Array.from(collected);
            const validated = list.length ? await this.validateProxies(list, this.validationTarget) : [];
            if (validated.length) {
                this.proxies = validated;
                this.proxyIndex = 0;
                this.proxyHealth.clear();   // fresh start for new list
                this.logger.log(`Proxy validation: ${validated.length}/${list.length} alive`);
            } else if (list.length) {
                this.proxies = manual;
                this.proxyIndex = 0;
                this.logger.warn(`Proxy validation: 0/${list.length} alive — ${manual.length ? 'using PROXY_LIST' : 'using own IP'}`);
            } else {
                this.logger.warn('Proxy refresh returned 0 proxies — keeping previous list');
            }
            this.sourceStatus = statuses;
            this.lastRefresh = new Date().toISOString();
            this.logger.log(`Proxy refresh done: ${this.proxies.length} total (${statuses.filter(s => s.ok).length}/${statuses.length} sources ok)`);
            return { total: this.proxies.length, sources: statuses };
        } finally {
            this.refreshing = false;
        }
    }

    private getManualProxies(): string[] {
        const rawList = (process.env['PROXY_LIST'] || '')
            .split(',')
            .map(p => p.trim())
            .filter(Boolean);

        const normalized = rawList
            .map(proxy => this.normalizeProxyLine(proxy, 'http'))
            .filter((proxy): proxy is string => !!proxy);

        return Array.from(new Set(normalized));
    }

    private createProxyAgent(proxy: string) {
        return (proxy.startsWith('socks4://') || proxy.startsWith('socks5://'))
            ? new SocksProxyAgent(proxy)
            : new HttpsProxyAgent(proxy);
    }

    private isProxySuspectResponse(status: number, body: unknown): boolean {
        if ([403, 407, 429, 502, 503, 504].includes(status)) return true;
        const text = typeof body === 'string' ? body.slice(0, 2000) : '';
        return /proxy authentication|required proxy|proxy error|tunnel connection failed|connection refused|access denied|request blocked/i.test(text);
    }

    private async pingProxy(proxy: string, timeoutMs = this.validationTimeoutMs): Promise<boolean> {
        const targets = [
            'https://api.ipify.org/?format=json',
            'http://api.ipify.org/?format=json',
        ];

        try {
            const checks = targets.map(async target => {
                const agent = this.createProxyAgent(proxy);
                const r = await axios.get<any>(target, {
                    timeout: timeoutMs,
                    signal: AbortSignal.timeout(timeoutMs),
                    httpAgent: agent,
                    httpsAgent: agent,
                    proxy: false,
                    validateStatus: s => s >= 200 && s < 300,
                });
                return !!r.data?.ip;
            });
            const results = await Promise.allSettled(checks);
            return results.some(result => result.status === 'fulfilled' && result.value);
        } catch {
            return false;
        }
    }

    private async validateProxies(list: string[], limit = this.maxProxies): Promise<string[]> {
        const alive: string[] = [];
        for (let i = 0; i < list.length && alive.length < limit; i += this.validationConcurrency) {
            const batch = list.slice(i, i + this.validationConcurrency);
            const results = await Promise.all(batch.map(async p => ({ p, ok: await this.pingProxy(p) })));
            for (const { p, ok } of results) if (ok) alive.push(p);
            if (alive.length >= limit) break;
        }
        return alive.slice(0, limit);
    }

    private normalizeProxyLine(raw: string, defaultProto: string): string | null {
        const token = raw.split(/[,\s;]/)[0]?.trim();
        if (!token || token.startsWith('#')) return null;

        const allowed = new Set(['http', 'https', 'socks4', 'socks5']);
        const withProto = /^(socks5|socks4|https?):\/\//i.test(token)
            ? token
            : `${defaultProto}://${token}`;

        try {
            const parsed = new URL(withProto);
            const protocol = parsed.protocol.replace(':', '').toLowerCase();
            if (!allowed.has(protocol)) return null;
            if (!parsed.hostname || !parsed.port) return null;
            const port = Number(parsed.port);
            if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
            if (/^(0\.0\.0\.0|127\.|localhost$)/i.test(parsed.hostname)) return null;

            const auth = parsed.username
                ? `${decodeURIComponent(parsed.username)}${parsed.password ? `:${decodeURIComponent(parsed.password)}` : ''}@`
                : '';
            return `${protocol}://${auth}${parsed.hostname}:${port}`;
        } catch {
            return null;
        }
    }

    async testProxy(input?: { proxy?: string; index?: number }): Promise<{
        mode:        'proxy' | 'own-ip';
        proxy:       { protocol: string; host: string; port: string; hasAuth: boolean } | null;
        working:     boolean;
        latencyMs:   number;
        outboundIp:  string | null;
        error?:      string;
    }> {
        let raw: string | undefined;
        if (input?.proxy) raw = input.proxy;
        else if (typeof input?.index === 'number') raw = this.proxies[input.index];
        else if (this.proxies.length) raw = this.proxies[this.proxyIndex % this.proxies.length];

        const TARGET = 'https://api.ipify.org/?format=json';
        const t0 = Date.now();

        const parseProxy = (r: string) => {
            const m = r.match(/^(socks5|socks4|https?):\/\/(?:([^:@]+)(?::[^@]+)?@)?([^:\/]+)(?::(\d+))?/i);
            if (!m) return null;
            return { protocol: m[1].toLowerCase(), host: m[3], port: m[4] ?? '', hasAuth: /@/.test(r) };
        };

        if (!raw) {
            // Own-IP test
            try {
                const r = await axios.get<any>(TARGET, { timeout: 6000 });
                return {
                    mode: 'own-ip', proxy: null,
                    working: true, latencyMs: Date.now() - t0,
                    outboundIp: r.data?.ip || null,
                };
            } catch (e: any) {
                return {
                    mode: 'own-ip', proxy: null,
                    working: false, latencyMs: Date.now() - t0,
                    outboundIp: null, error: e?.code || e?.message || 'failed',
                };
            }
        }

        const meta = parseProxy(raw);
        const agent = this.createProxyAgent(raw);
        try {
            const r = await axios.get<any>(TARGET, {
                timeout: 8000,
                httpAgent: agent, httpsAgent: agent,
                proxy: false,
            });
            return {
                mode: 'proxy', proxy: meta,
                working: true, latencyMs: Date.now() - t0,
                outboundIp: r.data?.ip || null,
            };
        } catch (e: any) {
            return {
                mode: 'proxy', proxy: meta,
                working: false, latencyMs: Date.now() - t0,
                outboundIp: null,
                error: e?.code || (e?.message || '').slice(0, 80) || 'failed',
            };
        }
    }

    getProxyStats() {
        const now = Date.now();
        const masked = this.proxies.map((raw, i) => {
            let protocol = 'http';
            let host = raw;
            let port = '';
            const m = raw.match(/^(socks5|socks4|https?):\/\/(?:([^:@]+)(?::[^@]+)?@)?([^:\/]+)(?::(\d+))?/i);
            if (m) {
                protocol = m[1].toLowerCase();
                host     = m[3];
                port     = m[4] ?? '';
            }
            const h = this.proxyHealth.get(raw);
            const dead = !!(h && h.deadUntil > now);
            return {
                index:    i,
                protocol,
                host,
                port,
                hasAuth:  /@/.test(raw),
                active:   i === (this.proxyIndex % Math.max(this.proxies.length, 1)),
                dead,
                fails:    h?.fails    ?? 0,
                deadUntil: dead ? new Date(h!.deadUntil).toISOString() : null,
            };
        });
        const deadCount = masked.filter(p => p.dead).length;
        // Clean up expired domain cooldowns and compute count
        const activeCooldowns: { host: string; remainingSec: number }[] = [];
        for (const [host, until] of this.domainCooldown.entries()) {
            if (until <= now) this.domainCooldown.delete(host);
            else activeCooldowns.push({ host, remainingSec: Math.ceil((until - now) / 1000) });
        }
        return {
            total:        this.proxies.length,
            alive:        this.proxies.length - deadCount,
            dead:         deadCount,
            currentIndex: this.proxies.length ? this.proxyIndex % this.proxies.length : 0,
            rotations:    this.proxyIndex,
            proxies:      masked,
            domainCooldowns: activeCooldowns,
            health: {
                deadAfterFails:   this.PROXY_DEAD_AFTER,
                reviveMinutes:    Math.round(this.PROXY_REVIVE_MS / 60_000),
                domainCooldownSec: Math.round(this.DOMAIN_COOLDOWN_MS / 1000),
                proxyFetchTimeoutMs: this.proxyFetchTimeoutMs,
            },
            autoRefresh: {
                enabled:         this.autoRefreshEnabled,
                available:       this.sources.length > 0,
                sourceMode:      this.usingDefaultProxySources ? 'default' : 'env',
                intervalMinutes: this.refreshMinutes,
                maxProxies:      this.maxProxies,
                candidateLimit:  this.validationCandidateLimit,
                validationTarget: this.validationTarget,
                manualCount:     this.getManualProxies().length,
                lastRefresh:     this.lastRefresh,
                refreshing:      this.refreshing,
                sources:         this.sourceStatus.length
                    ? this.sourceStatus
                    : this.sources.map(s => ({ url: s.url, protocol: s.protocol, ok: false, count: 0, fetchedAt: '' })),
            },
        };
    }

    // ── CMS PATTERNS ─────────────────────────────────────────────────────────
    private readonly CMS_PATTERNS: Array<{
        name: string;
        patterns: RegExp[];
        versionPatterns?: RegExp[];
        fileProbes?: Array<{ path: string; extractor: (b: string) => string | null }>;
        headerKeys?: Array<{ key: string; pattern: RegExp; versionPattern?: RegExp }>;
        cookieKeys?: RegExp[];
    }> = [
        {
            name: 'WordPress',
            patterns: [
                /\/wp-content\//i, /\/wp-includes\//i, /wp-json/i, /wp-emoji/i,
                /wp-block/i, /\/wp-content\/uploads\//i, /\/wp-content\/themes\//i,
                /\/wp-content\/plugins\//i, /class="wp-/i, /wpb_wrapper/i,
                /wpcf7/i, /elementor/i, /revslider/i, /wpml/i,
            ],
            versionPatterns: [
                /var\s+_wpVersion\s*=\s*['"]([^'"]+)['"]/i,
                /wordpress\.org\/\?v=([\d.]+)/i,
                /"wp_version"\s*:\s*"([\d.]+)"/i,
                /wp-includes\/[^"']*\?ver=([\d.]+)/i,
                /<meta[^>]+generator[^>]+WordPress\s+([\d.]+)/i,
                /wp-embed\.min\.js\?ver=([\d.]+)/i,
            ],
            cookieKeys: [/wordpress_/i, /wordpress_logged_in/i, /wp-settings-/i],
            fileProbes: [
                {
                    path: '/wp-json/',
                    extractor: b => {
                        try {
                            const j = JSON.parse(b);
                            return j?.generator?.match(/WordPress\/([\d.]+)/i)?.[1] ||
                                (j?.description ? 'detected' : null);
                        } catch { return null; }
                    },
                },
                {
                    path: '/?feed=rss2',
                    extractor: b => b.match(/<generator>[^<]*wordpress[^<]*\?v=([\d.]+)/i)?.[1] ||
                        (b.includes('wordpress') ? 'detected' : null),
                },
                {
                    path: '/readme.html',
                    extractor: b => b.match(/[Vv]ersion[:\s]+([\d.]+)/)?.[1] || null,
                },
                {
                    path: '/wp-login.php',
                    extractor: b => {
                        const ver = b.match(/wp-includes\/[^"']*\?ver=([\d.]+)/)?.[1]
                            || b.match(/ver=([\d.]+)/)?.[1];
                        return b.includes('WordPress') ? (ver || 'detected') : null;
                    },
                },
                {
                    path: '/wp-links-opml.php',
                    extractor: b => b.match(/generator="WordPress\/([\d.]+)"/i)?.[1] || null,
                },
                {
                    path: '/wp-json/wp/v2/',
                    extractor: b => {
                        try { const j = JSON.parse(b); return j?.namespace ? 'detected' : null; }
                        catch { return null; }
                    },
                },
                {
                    path: '/sitemap_index.xml',
                    extractor: b => b.match(/wordpress.*?([\d.]+)/i)?.[1] ||
                        (b.includes('wp-sitemap') ? 'detected' : null),
                },
            ],
        },
        {
            name: 'Bitrix',
            patterns: [
                /\/bitrix\/js\//i, /\/bitrix\/templates\//i, /\/bitrix\/components\//i,
                /\/bitrix\/cache\//i, /BX\.ready/i, /BX\.message/i, /bitrix_sessid/i,
                /1c-bitrix/i, /bitrixcloud/i, /\/upload\/resize_cache\//i,
                /BXMainFilter/i, /bitrix\/admin/i, /\/bitrix\/tools\//i,
            ],
            versionPatterns: [
                /BX\.message\(\{[^}]*"version"\s*:\s*"([\d.]+)"/i,
                /"VERSION"\s*:\s*"([\d.]+)"[^}]*bitrix/i,
                /1C-Bitrix[^;]*;\s*v\.([\d.]+)/i,
                /bitrix[^"']*version[^"']*['"]([\d.]+)['"]/i,
            ],
            cookieKeys: [/BITRIX_SM_/i, /BX_USER_ID/i],
            headerKeys: [
                { key: 'x-powered-cms', pattern: /bitrix/i },
                { key: 'set-cookie', pattern: /BITRIX_SM/i },
            ],
            fileProbes: [
                {
                    path: '/bitrix/modules/main/install/version.php',
                    extractor: b => b.match(/["']VERSION["']\s*=>\s*["']([\d.]+)["']/i)?.[1]
                        || b.match(/VERSION\s*=\s*["']([\d.]+)["']/i)?.[1] || null,
                },
                {
                    path: '/bitrix/admin/index.php',
                    extractor: b => {
                        const ver = b.match(/(?:ver|version)[=:]["']?([\d.]+)/i)?.[1];
                        return b.includes('Bitrix') ? (ver || 'detected') : null;
                    },
                },
                {
                    path: '/bitrix/js/main/core/core.js',
                    extractor: b => b.match(/version['"]\s*:\s*['"]?([\d.]+)/i)?.[1] || null,
                },
                {
                    path: '/bitrix/components/bitrix/main.ui.grid/templates/.default/script.js',
                    extractor: b => b.match(/version['"]\s*:\s*['"]?([\d.]+)/i)?.[1] || null,
                },
            ],
        },
        {
            name: 'Joomla',
            patterns: [
                /\/components\/com_/i, /\/media\/jui\//i, /\/media\/system\/js\//i,
                /Joomla!/i, /option=com_/i, /\/media\/jui\/js\//i,
                /joomla\.org/i, /\/modules\/mod_/i,
            ],
            versionPatterns: [
                /Joomla!\s*([\d.]+)/i,
                /joomla[^"']*version[^"']*['"]([\d.]+)['"]/i,
            ],
            cookieKeys: [/joomla_user_state/i, /joomla_[a-z]+/i],
            fileProbes: [
                {
                    path: '/administrator/manifests/files/joomla.xml',
                    extractor: b => b.match(/<version>([\d.]+)<\/version>/i)?.[1] || null,
                },
                {
                    path: '/administrator/',
                    extractor: b => {
                        const ver = b.match(/Joomla!\s*([\d.]+)/i)?.[1];
                        return b.includes('Joomla') ? (ver || 'detected') : null;
                    },
                },
                {
                    path: '/language/en-GB/en-GB.xml',
                    extractor: b => b.match(/<version>([\d.]+)<\/version>/i)?.[1] || null,
                },
                {
                    path: '/joomla.xml',
                    extractor: b => b.match(/<version>([\d.]+)<\/version>/i)?.[1] || null,
                },
                {
                    path: '/includes/version.php',
                    extractor: b => b.match(/RELEASE\s*=\s*['"]?([\d.]+)/i)?.[1]
                        || b.match(/DEV_LEVEL\s*=\s*['"]?(\d+)/i)?.[1] || null,
                },
            ],
        },
        {
            name: 'Drupal',
            patterns: [
                /Drupal\.settings/i, /\/sites\/default\/files\//i,
                /\/sites\/all\/modules\//i, /drupal\.js/i,
                /\/core\/misc\/drupal\.js/i, /data-drupal-/i,
                /\/modules\/contrib\//i, /\/themes\/contrib\//i,
            ],
            versionPatterns: [
                /Drupal\s+([\d.]+)/i,
                /"drupal_version"\s*:\s*"([\d.]+)"/i,
            ],
            cookieKeys: [/SESS[a-f0-9]{32}/i, /SSESS[a-f0-9]{32}/i],
            headerKeys: [{ key: 'x-generator', pattern: /Drupal/, versionPattern: /Drupal\s*([\d.]+)/i }],
            fileProbes: [
                {
                    path: '/CHANGELOG.txt',
                    extractor: b => b.match(/Drupal\s+([\d.]+)/i)?.[1] || null,
                },
                {
                    path: '/core/CHANGELOG.txt',
                    extractor: b => b.match(/Drupal\s+([\d.]+)/i)?.[1] || null,
                },
                {
                    path: '/core/package.json',
                    extractor: b => { try { return JSON.parse(b)?.version || null; } catch { return null; } },
                },
                {
                    path: '/core/core.services.yml',
                    extractor: b => b.includes('drupal') ? 'detected' : null,
                },
                {
                    path: '/core/lib/Drupal.php',
                    extractor: b => b.match(/VERSION\s*=\s*['"]([^'"]+)['"]/)?.[1] || null,
                },
            ],
        },
        {
            name: 'MODX',
            patterns: [
                /powered by MODX/i, /modx\.com/i, /\/assets\/components\//i,
                /\/assets\/snippets\//i, /MODx/i, /modxcloud/i,
                /class="modx/i, /modx\.reloadPage/i,
            ],
            versionPatterns: [
                /MODX\s+Revolution\s+([\d.]+)/i,
                /MODX\s+([\d.]+)/i,
            ],
            fileProbes: [
                {
                    path: '/manager/',
                    extractor: b => {
                        const ver = b.match(/MODX(?:\s+Revolution)?\s*([\d.]+(?:-[a-z]+[\d]*)?)/i)?.[1];
                        return (b.includes('MODX') || b.includes('modx')) ? (ver || 'detected') : null;
                    },
                },
                {
                    path: '/core/cache/mgr/web/config.cache.php',
                    extractor: b => b.match(/modx_version.*?([\d.]+)/i)?.[1] || null,
                },
                {
                    path: '/setup/index.php',
                    extractor: b => {
                        const ver = b.match(/MODX(?:\s+Revolution)?\s*([\d.]+)/i)?.[1];
                        return (b.includes('MODX')) ? (ver || 'detected') : null;
                    },
                },
            ],
        },
        {
            name: 'OctoberCMS',
            patterns: [/october\.cms/i, /\/plugins\/rainlab\//i, /ocms/i, /\/modules\/system\//i],
            fileProbes: [
                {
                    path: '/backend/',
                    extractor: b => b.includes('October') ? 'detected' : null,
                },
            ],
        },
        {
            name: 'Shopify',
            patterns: [/cdn\.shopify\.com/i, /Shopify\.theme/i, /myshopify\.com/i, /shopify\.com\/s\/files/i],
            headerKeys: [
                { key: 'x-shopid', pattern: /.+/ },
                { key: 'x-shopify-stage', pattern: /.+/ },
            ],
            cookieKeys: [/_shopify_/i, /cart_currency/i],
        },
        {
            name: 'Ghost',
            patterns: [/ghost\.org/i, /\/ghost\/api\//i, /content="Ghost/i, /ghost-sdk/i],
            versionPatterns: [/Ghost\s*([\d.]+)/i],
            fileProbes: [
                {
                    path: '/ghost/api/v4/admin/',
                    extractor: b => { try { const j = JSON.parse(b); return j?.version || null; } catch { return null; } },
                },
            ],
        },
        {
            name: 'TYPO3',
            patterns: [/typo3/i, /\/typo3conf\//i, /TYPO3\.CMS/i, /\/typo3\/sysext\//i],
            cookieKeys: [/fe_typo_user/i, /be_typo_user/i],
            fileProbes: [
                {
                    path: '/typo3/index.php',
                    extractor: b => {
                        const ver = b.match(/TYPO3\s*([\d.]+)/i)?.[1];
                        return b.includes('TYPO3') ? (ver || 'detected') : null;
                    },
                },
            ],
        },
        {
            name: 'Wix',
            patterns: [/static\.wixstatic\.com/i, /wix\.com/i, /wixsite\.com/i, /wix-warmup-data/i],
        },
        {
            name: 'Squarespace',
            patterns: [/squarespace\.com/i, /static\.squarespace\.com/i, /squarespace-cdn\.com/i],
            cookieKeys: [/ss_cvr/i, /ss_cvi/i],
        },
        {
            name: 'Webflow',
            patterns: [/webflow\.com/i, /assets\.website-files\.com/i, /uploads-ssl\.webflow\.com/i],
            headerKeys: [{ key: 'x-wf-site', pattern: /.+/ }],
        },
        {
            name: 'Tilda',
            patterns: [/tilda\.cc/i, /tildacdn\.com/i, /tilda\.ws/i, /t-head__title/i],
        },
        {
            name: 'OpenCart',
            patterns: [
                /route=common\//i, /opencart/i, /catalog\/view\/theme/i, /index\.php\?route=/i,
                /route=product\//i, /route=checkout\//i, /\/image\/catalog\//i,
            ],
            versionPatterns: [
                /OpenCart\s+v?([\d.]+)/i,
                /oc_version['"]\s*:\s*['"]([\d.]+)['"]/i,
            ],
            cookieKeys: [/OCSESSID/i],
            fileProbes: [
                {
                    path: '/index.php?route=common/home',
                    extractor: b => b.includes('OpenCart') || b.includes('catalog/view') ? 'detected' : null,
                },
                {
                    path: '/CHANGELOG.md',
                    extractor: b => b.match(/OpenCart\s*v?([\d.]+)/i)?.[1] || b.match(/^##\s*([\d.]+)/m)?.[1] || null,
                },
                {
                    path: '/system/startup.php',
                    extractor: b => b.match(/VERSION\s*,\s*['"]([^'"]+)['"]/)?.[1] || null,
                },
                {
                    path: '/upload/system/startup.php',
                    extractor: b => b.match(/VERSION\s*,\s*['"]([^'"]+)['"]/)?.[1] || null,
                },
            ],
        },
        {
            name: 'PrestaShop',
            patterns: [
                /prestashop/i, /\/themes\/classic\//i, /id_product=/i, /prestashop\.com/i,
                /var prestashop/i, /\/modules\/ps_/i, /blockwishlist/i,
            ],
            versionPatterns: [
                /prestashop[^"']*version[^"']*['"]([\d.]+)['"]/i,
                /"version"\s*:\s*"([\d.]+)"[^}]*prestashop/i,
            ],
            cookieKeys: [/PrestaShop-/i, /id_cart/i, /id_wishlist/i],
            fileProbes: [
                {
                    path: '/app/version.php',
                    extractor: b => b.match(/_PS_VERSION_['"]\s*,\s*['"]([\d.]+)['"]/)?.[1]
                        || b.match(/'([\d]+\.[.\d]+)'/)?.[1] || null,
                },
                {
                    path: '/config/smarty.config.php',
                    extractor: b => b.match(/_PS_VERSION_['"]\s*,\s*['"]([\d.]+)['"]/)?.[1] || null,
                },
                {
                    path: '/js/tools.js',
                    extractor: b => b.includes('prestashop') ? 'detected' : null,
                },
                {
                    path: '/package.json',
                    extractor: b => {
                        try {
                            const j = JSON.parse(b);
                            return j?.version && b.includes('prestashop') ? j.version : null;
                        } catch { return null; }
                    },
                },
            ],
        },
        {
            name: 'Magento',
            patterns: [
                /\/skin\/frontend\//i, /Mage\.Cookies/i, /\/media\/catalog\//i,
                /Magento_/i, /\/pub\/static\//i, /magentoUserAlreadyLoggedIn/i,
                /var BLANK_URL/i, /require-config\.js/i, /\/mage\//i,
            ],
            versionPatterns: [
                /Magento\/([\d.]+)/i,
                /"magento_version"\s*:\s*"([\d.]+)"/i,
                /Mage\.VERSION\s*=\s*['"]([^'"]+)['"]/i,
            ],
            cookieKeys: [/mage-cache-storage/i, /mage-messages/i, /PHPSESSID/i],
            headerKeys: [
                { key: 'x-magento-vary', pattern: /.+/ },
                { key: 'x-magento-cache-debug', pattern: /.+/ },
            ],
            fileProbes: [
                {
                    path: '/magento_version',
                    extractor: b => b.match(/Magento\/([\d.]+)/i)?.[1] || (b.includes('Magento') ? 'detected' : null),
                },
                {
                    path: '/pub/static/version.txt',
                    extractor: b => b.trim().match(/^[\d.]+$/) ? b.trim() : null,
                },
                {
                    path: '/composer.json',
                    extractor: b => {
                        try {
                            const j = JSON.parse(b);
                            if (j?.name?.includes('magento')) return j?.version || 'detected';
                            return null;
                        } catch { return null; }
                    },
                },
            ],
        },
        {
            name: 'DLE',
            patterns: [
                /DataLife Engine/i, /\/engine\/classes\//i, /\/engine\/ajax\//i,
                /dle_root/i, /\/engine\/engine\.js/i, /dle_verify/i, /dle_login_hash/i,
                /powered by DataLife/i, /\/templates\/[^/]+\/css\//i,
            ],
            versionPatterns: [
                /DataLife Engine\s*v?\s*([\d.]+)/i,
                /DLE\s*v?([\d.]+)/i,
                /dle_version['"]\s*:\s*['"]([\d.]+)['"]/i,
            ],
            cookieKeys: [/dle_user/i, /dle_password/i, /dle_hash/i, /dle_newpm/i],
            fileProbes: [
                {
                    path: '/engine/engine.php',
                    extractor: b => b.includes('DataLife') || b.includes('DLE') ? 'detected' : null,
                },
                {
                    path: '/engine/data/config.php',
                    extractor: b => b.match(/['"]version['"]\s*=>\s*['"]([^'"]+)['"]/i)?.[1]
                        || b.match(/version.*?([\d.]+)/i)?.[1]
                        || (b.includes('DLE') ? 'detected' : null),
                },
                {
                    path: '/engine/classes/templates.class.php',
                    extractor: b => b.match(/version[^=]*=\s*['"]([\d.]+)['"]/i)?.[1]
                        || (b.includes('DataLife') ? 'detected' : null),
                },
            ],
        },
        {
            name: 'UMI.CMS',
            patterns: [
                /umi\.cms/i, /__umi_options/i, /umiOnReady/i,
                /\/styles\/\d+\//i, /\/files\/attachments\//i,
                /umiObjectProps/i,
            ],
            fileProbes: [
                {
                    path: '/udata//system/version/',
                    extractor: b => {
                        try { const j = JSON.parse(b); return j?.result?.version || (b.includes('umi') ? 'detected' : null); }
                        catch { return b.includes('umi') ? 'detected' : null; }
                    },
                },
            ],
        },
        {
            name: 'CS-Cart',
            patterns: [
                /cs-cart/i, /cscart/i, /fn_get_contents/i,
                /\/design\/themes\//i, /var Tygh/i, /Tygh\.$/i,
                /dispatch\[/i,
            ],
            versionPatterns: [
                /CS-Cart\s*v?([\d.]+)/i,
                /cscart_version['"]\s*:\s*['"]([\d.]+)['"]/i,
                /Tygh\.__version\s*=\s*['"]([\d.]+)['"]/i,
            ],
            cookieKeys: [/se_session/i, /sy_session_data/i],
            fileProbes: [
                {
                    path: '/js/tygh/core.js',
                    extractor: b => {
                        const ver = b.match(/version['"]\s*:\s*['"]([\d.]+)['"]/i)?.[1];
                        return b.includes('Tygh') ? (ver || 'detected') : null;
                    },
                },
                {
                    path: '/var/themes_repository/responsive/manifest.ini',
                    extractor: b => b.match(/version\s*=\s*([\d.]+)/i)?.[1] || null,
                },
            ],
        },
        {
            name: 'WooCommerce',
            patterns: [/woocommerce/i, /\/wc-api\//i, /class="woocommerce/i, /wc_add_to_cart/i],
        },
        {
            name: 'Laravel',
            patterns: [/laravel_session/i, /csrf-token.*laravel/i, /laravel\.com/i],
            cookieKeys: [/laravel_session/i, /XSRF-TOKEN/i],
            headerKeys: [{ key: 'x-powered-by', pattern: /PHP/i }],
        },
        {
            name: 'UzGovCMS',
            patterns: [/hukumat\.uz/i, /e-hukumat/i, /uzgov/i, /davlat-xizmatlari/i],
        },
        {
            name: 'phpBB',
            patterns: [/phpbb/i, /\/styles\/prosilver\//i, /viewtopic\.php/i, /class="phpbb/i],
            fileProbes: [{ path: '/index.php', extractor: b => b.match(/phpBB\s*([\d.]+)/i)?.[1] || (b.includes('phpBB') ? 'detected' : null) }],
        },
        {
            name: 'vBulletin',
            patterns: [/vbulletin/i, /vb_postbit/i, /showthread\.php/i, /class="vbmenu_/i],
            versionPatterns: [/vBulletin\s*([\d.]+)/i],
        },
        {
            name: 'XenForo',
            patterns: [/xenforo/i, /xf-body/i, /\.xf\./i, /class="xf-/i],
            versionPatterns: [/XenForo\s*([\d.]+)/i],
        },
        {
            name: 'MyBB',
            patterns: [/mybb/i, /class="mybb_/i, /forumdisplay\.php/i],
        },
        {
            name: 'Discourse',
            patterns: [/discourse/i, /ember-application/i, /data-discourse-/i],
            headerKeys: [{ key: 'x-discourse-route', pattern: /.+/ }],
        },
        {
            name: 'MediaWiki',
            patterns: [/mediawiki/i, /\/w\/index\.php\?title=/i, /id="mw-/i, /class="mw-/i, /mw\.config/i],
            versionPatterns: [/MediaWiki\s*([\d.]+)/i],
            fileProbes: [{ path: '/w/api.php?action=query&meta=siteinfo&format=json', extractor: b => { try { const j = JSON.parse(b); return j?.query?.general?.generator?.match(/MediaWiki\s*([\d.]+)/i)?.[1] || (j?.query ? 'detected' : null); } catch { return null; } } }],
        },
        {
            name: 'DokuWiki',
            patterns: [/dokuwiki/i, /doku\.php/i, /class="dokuwiki/i],
            versionPatterns: [/DokuWiki\s*([\d.]+)/i],
        },
        {
            name: 'Confluence',
            patterns: [/confluence/i, /atlassian/i, /class="confluence-/i, /aui-page-/i],
        },
        {
            name: 'Moodle',
            patterns: [/moodle/i, /\/mod\/forum\//i, /id="page-site-index"/i, /class="moodle/i, /MoodleTranslation/i],
            versionPatterns: [/Moodle\s*([\d.]+)/i],
            cookieKeys: [/MoodleSession/i],
            fileProbes: [{ path: '/lib/upgrade.txt', extractor: b => b.match(/=== ([\d.]+) ===/)?.[1] || null }],
        },
        {
            name: 'Canvas LMS',
            patterns: [/instructure/i, /canvas-lms/i, /canvas_application_name/i],
        },
        {
            name: 'Bitrix24',
            patterns: [/bitrix24/i, /crm\.bitrix/i, /b24-/i],
        },
        {
            name: 'AmoCRM',
            patterns: [/amocrm/i, /amoCRM/i],
        },
        {
            name: 'Craft CMS',
            patterns: [
                /craftcms/i, /Craft\.CMS/i, /CRAFT_CSRF_TOKEN/i,
                /\/cpresources\//i, /\/index\.php\?p=/i, /craft\.js/i,
            ],
            versionPatterns: [/Craft CMS\s*([\d.]+)/i],
            cookieKeys: [/CraftSessionId/i, /CRAFT_CSRF_TOKEN/i],
            headerKeys: [{ key: 'x-powered-by', pattern: /Craft CMS/i, versionPattern: /Craft CMS\s*([\d.]+)/i }],
        },
        {
            name: 'Concrete CMS',
            patterns: [
                /concrete5/i, /Concrete CMS/i, /\/concrete\/js\//i,
                /\/concrete\/css\//i, /ccm_/i, /data-area-handle/i,
            ],
            versionPatterns: [/concrete5\s*-\s*([\d.]+)/i, /Concrete CMS\s*([\d.]+)/i],
            cookieKeys: [/CONCRETE5/i, /ccmUserHash/i],
        },
        {
            name: 'SilverStripe',
            patterns: [/silverstripe/i, /\/framework\/thirdparty\//i, /\/mysite\/javascript\//i, /SecurityID/i],
            cookieKeys: [/PastMember/i, /SilverStripe/i],
        },
        {
            name: 'Umbraco',
            patterns: [
                /umbraco/i, /\/umbraco\//i, /\/umbraco_client\//i,
                /DependencyHandler\.axd/i, /umbraco\.surface/i,
            ],
            versionPatterns: [/Umbraco\s*([\d.]+)/i],
            cookieKeys: [/UMB_UCONTEXT/i, /UMB-XSRF/i, /UMB_PREVIEW/i],
            headerKeys: [{ key: 'x-umbraco-version', pattern: /.+/, versionPattern: /([\d.]+)/ }],
        },
        {
            name: 'Kentico Xperience',
            patterns: [
                /kentico/i, /xperience/i, /\/CMSPages\//i, /\/CMSScripts\//i,
                /\/CMSPages\/GetResource\.ashx/i, /\/getmedia\//i,
            ],
            versionPatterns: [/Kentico\s*([\d.]+)/i, /Xperience\s*([\d.]+)/i],
            cookieKeys: [/CMSPreferredCulture/i, /CMSCsrfCookie/i, /CMSCurrentTheme/i, /CMSCookieLevel/i],
            headerKeys: [{ key: 'x-powered-by', pattern: /Kentico|Xperience/i }],
        },
        {
            name: 'Sitecore',
            patterns: [
                /sitecore/i, /\/sitecore\//i, /\/-\/media\//i,
                /\/layouts\/system\//i, /sc_mode=/i, /Sitecore Experience/i,
            ],
            versionPatterns: [/Sitecore\s*([\d.]+)/i],
            cookieKeys: [/SC_ANALYTICS_GLOBAL_COOKIE/i, /sitecore/i],
            headerKeys: [{ key: 'x-powered-by', pattern: /Sitecore/i }],
        },
        {
            name: 'Adobe Experience Manager',
            patterns: [
                /Adobe Experience Manager/i, /\bAEM\b/i, /\/etc\.clientlibs\//i,
                /\/content\/dam\//i, /\/libs\/granite\//i, /cq:template/i,
            ],
            versionPatterns: [/Adobe Experience Manager\s*([\d.]+)/i],
            cookieKeys: [/login-token/i, /cq-authoring-mode/i],
            headerKeys: [{ key: 'x-dispatcher', pattern: /.+/ }],
        },
        {
            name: 'Liferay',
            patterns: [
                /liferay/i, /Liferay\.ThemeDisplay/i, /\/o\/frontend-/i,
                /\/o\/classic-theme\//i, /\/documents\//i,
            ],
            versionPatterns: [/Liferay\s*([\d.]+)/i],
            cookieKeys: [/GUEST_LANGUAGE_ID/i, /LFR_SESSION_STATE/i, /COMPANY_ID/i],
            headerKeys: [{ key: 'liferay-portal', pattern: /.+/, versionPattern: /Liferay Portal\s*([\d.]+)/i }],
        },
        {
            name: 'DNN',
            patterns: [
                /DotNetNuke/i, /\bDNN\b/i, /\/DesktopModules\//i,
                /\/Portals\/_default\//i, /dnn_/i,
            ],
            versionPatterns: [/DotNetNuke\s*([\d.]+)/i, /DNN\s*([\d.]+)/i],
            cookieKeys: [/\.DOTNETNUKE/i, /dnn_IsMobile/i],
        },
        {
            name: 'Orchard Core',
            patterns: [/OrchardCore/i, /Orchard\.Core/i, /\/OrchardCore\./i, /powered by Orchard/i],
            versionPatterns: [/Orchard Core\s*([\d.]+)/i],
        },
        {
            name: 'SharePoint',
            patterns: [
                /Microsoft SharePoint/i, /\/_layouts\/15\//i, /\/_catalogs\//i,
                /\/_vti_bin\//i, /SharePointPageContextInfo/i,
            ],
            versionPatterns: [/SharePoint\s*([\d.]+)/i],
            cookieKeys: [/FedAuth/i, /rtFa/i],
            headerKeys: [
                { key: 'microsoftsharepointteamservices', pattern: /.+/, versionPattern: /([\d.]+)/ },
                { key: 'x-sharepointhealthscore', pattern: /.+/ },
            ],
        },
        {
            name: 'Plone',
            patterns: [/plone/i, /portal_css/i, /portal_javascripts/i, /data-portal-url/i],
            versionPatterns: [/Plone\s*([\d.]+)/i],
            cookieKeys: [/__ac/i, /I18N_LANGUAGE/i],
        },
        {
            name: 'HubSpot CMS',
            patterns: [
                /hubspot/i, /hs-scripts\.com/i, /hsforms\.net/i,
                /js\.hsforms\.net/i, /_hsq/i, /hubspotutk/i,
            ],
            cookieKeys: [/hubspotutk/i, /__hstc/i, /__hssc/i],
        },
        {
            name: 'Blogger',
            patterns: [/blogger\.com/i, /blogspot\.com/i, /\/feeds\/posts\/default/i, /Blogger Template/i],
            versionPatterns: [/Blogger\s*([\d.]+)/i],
        },
        {
            name: 'Weebly',
            patterns: [/weebly\.com/i, /cdn2\.editmysite\.com/i, /Weebly\.com/i, /wsite-/i],
        },
        {
            name: 'Duda',
            patterns: [/duda\.co/i, /static-cdn\.multiscreensite\.com/i, /dmRespCol/i, /dmBody/i],
        },
        {
            name: 'Framer',
            patterns: [/framerusercontent\.com/i, /framer-motion/i, /data-framer-/i, /__framer/i],
        },
        {
            name: 'Google Sites',
            patterns: [/sites\.google\.com/i, /googlesites/i, /google-site-verification/i, /jotspot/i],
        },
        {
            name: 'Textpattern',
            patterns: [/textpattern/i, /txp-/i, /\/textpattern\/css\.php/i],
            cookieKeys: [/txp_login/i],
        },
        {
            name: 'ExpressionEngine',
            patterns: [/ExpressionEngine/i, /exp:channel/i, /\/themes\/ee\//i, /EE\.publish/i],
            cookieKeys: [/exp_tracker/i, /exp_last_visit/i],
        },
        {
            name: 'Statamic',
            patterns: [/statamic/i, /\/vendor\/statamic\//i, /Statamic\.csrfToken/i],
            cookieKeys: [/statamic/i],
        },
    ];

    // ── CMS → DETAILED CATEGORY MAP ──────────────────────────────────────────
    private readonly CMS_CATEGORY_MAP: Partial<Record<string, SiteCategory>> = {
        // Traditional CMS
        WordPress: 'CMS', Joomla: 'CMS', Drupal: 'CMS', Bitrix: 'CMS',
        MODX: 'CMS', OctoberCMS: 'CMS', TYPO3: 'CMS', DLE: 'CMS',
        'UMI.CMS': 'CMS', UzGovCMS: 'CMS', 'Craft CMS': 'CMS',
        'Concrete CMS': 'CMS', SilverStripe: 'CMS', Umbraco: 'CMS',
        'Kentico Xperience': 'CMS', Sitecore: 'CMS',
        'Adobe Experience Manager': 'CMS', Liferay: 'CMS', DNN: 'CMS',
        'Orchard Core': 'CMS', SharePoint: 'CMS', Plone: 'CMS',
        Textpattern: 'CMS', ExpressionEngine: 'CMS', Statamic: 'CMS',
        // E-commerce
        Shopify: 'E-commerce CMS', WooCommerce: 'E-commerce CMS',
        Magento: 'E-commerce CMS', PrestaShop: 'E-commerce CMS',
        OpenCart: 'E-commerce CMS', 'CS-Cart': 'E-commerce CMS',
        // Web Builders
        Wix: 'Web Builder / No-Code Platform', Squarespace: 'Web Builder / No-Code Platform',
        Webflow: 'Web Builder / No-Code Platform', Tilda: 'Web Builder / No-Code Platform',
        Weebly: 'Web Builder / No-Code Platform', Duda: 'Web Builder / No-Code Platform',
        Framer: 'Web Builder / No-Code Platform', 'Google Sites': 'Web Builder / No-Code Platform',
        // Fullstack Frameworks
        'Next.js': 'Fullstack Framework', 'Nuxt.js': 'Fullstack Framework',
        SvelteKit: 'Fullstack Framework', Remix: 'Fullstack Framework', Astro: 'Fullstack Framework',
        // Backend Frameworks
        Laravel: 'Backend Framework', Django: 'Backend Framework',
        'Ruby on Rails': 'Backend Framework', 'Express.js': 'Backend Framework',
        'ASP.NET': 'Backend Framework', 'ASP.NET Core': 'Backend Framework',
        'Spring Boot': 'Backend Framework',
        FastAPI: 'Backend Framework', Flask: 'Backend Framework',
        Symfony: 'Backend Framework', CakePHP: 'Backend Framework',
        CodeIgniter: 'Backend Framework', Yii2: 'Backend Framework',
        // Frontend / Build tools
        Vite: 'Frontend Framework / SPA', 'SPA (Custom)': 'Frontend Framework / SPA',
        // Headless CMS
        Contentful: 'Headless CMS', Sanity: 'Headless CMS', Strapi: 'Headless CMS',
        Directus: 'Headless CMS', Prismic: 'Headless CMS', DatoCMS: 'Headless CMS',
        Storyblok: 'Headless CMS', Hygraph: 'Headless CMS', ButterCMS: 'Headless CMS',
        'Netlify CMS': 'Headless CMS', 'Payload CMS': 'Headless CMS',
        // Static Site Generators
        Gatsby: 'Static Site Generator (SSG)', Hugo: 'Static Site Generator (SSG)',
        Jekyll: 'Static Site Generator (SSG)', Eleventy: 'Static Site Generator (SSG)',
        VitePress: 'Static Site Generator (SSG)', Docusaurus: 'Static Site Generator (SSG)',
        Hexo: 'Static Site Generator (SSG)',
        // Blog Engines
        Ghost: 'Blog Engine', Blogger: 'Blog Engine',
        // Forum Engines
        phpBB: 'Forum Engine', vBulletin: 'Forum Engine', XenForo: 'Forum Engine',
        MyBB: 'Forum Engine', Discourse: 'Forum Engine',
        // Wiki Engines
        MediaWiki: 'Wiki Engine', DokuWiki: 'Wiki Engine', Confluence: 'Wiki Engine',
        // LMS
        Moodle: 'Learning Management System (LMS)', 'Canvas LMS': 'Learning Management System (LMS)',
        // CRM / ERP
        Bitrix24: 'CRM / ERP Web System', AmoCRM: 'CRM / ERP Web System',
        'HubSpot CMS': 'CRM / ERP Web System',
    };

    // ── FRAMEWORK PATTERNS ────────────────────────────────────────────────────
    private readonly FRAMEWORK_PATTERNS: Array<{
        name: string; patterns: RegExp[];
        headerKeys?: Array<{ key: string; pattern: RegExp; versionPattern?: RegExp }>;
        versionPatterns?: RegExp[];
    }> = [
        {
            name: 'Next.js',
            patterns: [/\/_next\/static\//i, /__NEXT_DATA__/i, /next\/dist\//i],
            headerKeys: [{ key: 'x-powered-by', pattern: /Next\.js/i, versionPattern: /Next\.js\s*([\d.]+)/i }],
            versionPatterns: [/"nextjs":"([\d.]+)"/i, /next\/([\d.]+)/i],
        },
        {
            name: 'Nuxt.js',
            patterns: [/\/_nuxt\//i, /__nuxt/i, /nuxtApp/i, /window\.__NUXT__/i],
        },
        {
            name: 'SvelteKit',
            patterns: [/\/_app\/immutable\//i, /__sveltekit/i, /sveltekit/i],
        },
        {
            name: 'Remix',
            patterns: [/__remixContext/i, /__remixRouteModules/i, /__remix_manifest/i],
        },
        {
            name: 'Astro',
            patterns: [/astro-island/i, /@astrojs/i, /astro:page-load/i],
        },
        {
            name: 'Vite',
            patterns: [
                /<script[^>]+type=["']module["'][^>]+src=["']\/assets\/index-[A-Za-z0-9_-]+\.js/i,
                /<link[^>]+rel=["']modulepreload["'][^>]+href=["']\/assets\//i,
            ],
        },
        {
            name: 'Django',
            patterns: [/csrfmiddlewaretoken/i, /django/i, /dj-static/i],
            versionPatterns: [/Django\/([\d.]+)/i],
        },
        {
            name: 'Ruby on Rails',
            patterns: [/authenticity_token/i, /rails-ujs/i, /turbolinks/i],
            headerKeys: [{ key: 'x-runtime', pattern: /[\d.]+/ }],
        },
        {
            name: 'Express.js',
            patterns: [],
            headerKeys: [{ key: 'x-powered-by', pattern: /Express/i }],
        },
        {
            name: 'ASP.NET',
            patterns: [/__VIEWSTATE/i, /\.aspx/i, /asp\.net/i, /WebResource\.axd/i],
            headerKeys: [
                { key: 'x-powered-by', pattern: /ASP\.NET/i, versionPattern: /ASP\.NET\s*([\d.]+)/i },
                { key: 'x-aspnet-version', pattern: /.+/, versionPattern: /([\d.]+)/ },
            ],
        },
        { name: 'Spring Boot', patterns: [/Whitelabel Error Page/i, /spring-boot/i] },
        { name: 'FastAPI', patterns: [/fastapi/i, /"openapi"/i] },
        { name: 'CodeIgniter', patterns: [/ci_session/i, /codeigniter/i] },
        { name: 'Symfony', patterns: [/symfony/i, /sf_redirect/i, /_wdt\//i] },
        { name: 'CakePHP', patterns: [/cakephp/i, /CAKEPHP/i] },
        { name: 'Yii2', patterns: [/yii2/i, /_csrf.*yii/i, /yii\.reloadableScripts/i] },
        {
            name: 'Flask',
            patterns: [/flask/i, /Werkzeug/i],
            headerKeys: [{ key: 'server', pattern: /Werkzeug/i, versionPattern: /Werkzeug\/([\d.]+)/i }],
        },
    ];

    // ── HEADLESS CMS ─────────────────────────────────────────────────────────
    private readonly HEADLESS_PATTERNS: Array<{ name: string; patterns: RegExp[] }> = [
        { name: 'Contentful', patterns: [/contentful\.com/i, /cdn\.contentful\.com/i] },
        { name: 'Sanity', patterns: [/sanity\.io/i, /cdn\.sanity\.io/i] },
        { name: 'Strapi', patterns: [/strapi/i] },
        { name: 'Directus', patterns: [/directus/i] },
        { name: 'Prismic', patterns: [/prismic\.io/i] },
        { name: 'DatoCMS', patterns: [/datocms\.com/i] },
        { name: 'Storyblok', patterns: [/storyblok\.com/i] },
        { name: 'Hygraph', patterns: [/hygraph\.com/i, /graphcms/i] },
        { name: 'ButterCMS', patterns: [/buttercms\.com/i] },
        { name: 'Netlify CMS', patterns: [/netlify-cms/i, /decap-cms/i] },
        { name: 'Payload CMS', patterns: [/payloadcms/i, /payload\.config/i] },
    ];

    // ── STATIC SITE ───────────────────────────────────────────────────────────
    private readonly STATIC_PATTERNS: Array<{
        name: string; patterns: RegExp[];
        headerKeys?: Array<{ key: string; pattern: RegExp; versionPattern?: RegExp }>;
        versionPatterns?: RegExp[];
    }> = [
        { name: 'Gatsby', patterns: [/___gatsby/i, /\/page-data\//i, /gatsby-chunk/i] },
        {
            name: 'Hugo',
            patterns: [/content="Hugo/i],
            headerKeys: [{ key: 'x-generator', pattern: /Hugo/i, versionPattern: /Hugo\s*([\d.]+)/i }],
            versionPatterns: [/Hugo\s*([\d.]+)/i],
        },
        { name: 'Jekyll', patterns: [/jekyll/i, /jekyll-theme/i] },
        { name: 'Eleventy', patterns: [/eleventy/i, /\/_11ty\//i] },
        { name: 'VitePress', patterns: [/vitepress/i] },
        { name: 'Docusaurus', patterns: [/docusaurus/i] },
        { name: 'Hexo', patterns: [/content="Hexo/i] },
    ];

    // ── JS FRAMEWORKS ─────────────────────────────────────────────────────────
    private readonly JS_FRAMEWORK_PATTERNS: Array<{ name: string; patterns: RegExp[] }> = [
        { name: 'React', patterns: [/react-dom/i, /__reactFiber/i, /ReactDOM/i, /react\.production\.min/i] },
        { name: 'Vue', patterns: [/vue\.js/i, /\[data-v-/i, /Vue\.component/i, /vue\.min\.js/i] },
        { name: 'Angular', patterns: [/ng-version/i, /angular\.min\.js/i, /NgModule/i] },
        { name: 'Svelte', patterns: [/svelte/i] },
        { name: 'Alpine', patterns: [/alpinejs/i, /x-data=/i] },
        { name: 'jQuery', patterns: [/jquery/i, /jQuery/i] },
        { name: 'HTMX', patterns: [/htmx\.org/i, /hx-get=/i] },
        { name: 'Ember', patterns: [/ember\.js/i] },
        { name: 'Qwik', patterns: [/q:container/i, /\/build\/q-/i, /qwik/i] },
        { name: 'Solid', patterns: [/solid-js/i, /data-hk=/i] },
        { name: 'Lit', patterns: [/lit-element/i, /lit-html/i] },
        { name: 'Stimulus', patterns: [/data-controller=/i, /stimulus/i] },
    ];

    // ── MAIN ─────────────────────────────────────────────────────────────────
    async detect(url: string, options: CmsDetectOptions = {}): Promise<CmsDetectionResult> {
        const baseUrl = this.normalizeUrl(url);
        const mode = options.mode === 'FAST' ? 'FAST' : 'FULL';
        const timeoutMs = this.normalizeTimeout(options.timeoutMs, mode);
        const cacheKey = `${baseUrl}:${mode}:${timeoutMs}`;

        // Cache hit → return early (refresh detectedAt)
        const cached = this.detectCache.get(cacheKey);
        if (cached && Date.now() < cached.exp) {
            return { ...cached.result, detectedAt: new Date() };
        }

        const signals: TechSignal[] = [];
        const rawSignals: Record<string, string> = {};
        let serverTech: string[] = [];
        let jsFrameworks: string[] = [];
        let httpStatus: number | null = null;
        let pageTitle: string | null = null;
        let mainPage_result: { html: string; headers: Record<string, string>; status: number } | null = null;
        rawSignals['_scan_mode'] = mode;

        try {
            if (mode === 'FAST') {
                const main = await this.fetchPage(baseUrl, 0, timeoutMs);
                mainPage_result = main;

                if (main) {
                    httpStatus = main.status;
                    const pageSignals = this.collectHtmlSignals(baseUrl, main.html, main.headers, rawSignals);
                    serverTech = pageSignals.serverTech;
                    jsFrameworks = pageSignals.jsFrameworks;
                    pageTitle = pageSignals.pageTitle;
                    signals.push(...pageSignals.signals);
                }
            } else {
                const [mainPage, robotsPage, sitemapPage] = await Promise.allSettled([
                    this.fetchPage(baseUrl, 0, timeoutMs),
                    this.fetchPage(baseUrl + '/robots.txt', 0, timeoutMs),
                    this.fetchPage(baseUrl + '/sitemap.xml', 0, timeoutMs),
                ]);

                const main = mainPage.status === 'fulfilled' ? mainPage.value : null;
                mainPage_result = main;
                const robots = robotsPage.status === 'fulfilled' ? robotsPage.value : null;
                const sitemap = sitemapPage.status === 'fulfilled' ? sitemapPage.value : null;

                if (main) {
                    httpStatus = main.status;
                    const pageSignals = this.collectHtmlSignals(baseUrl, main.html, main.headers, rawSignals);
                    serverTech = pageSignals.serverTech;
                    jsFrameworks = pageSignals.jsFrameworks;
                    pageTitle = pageSignals.pageTitle;
                    signals.push(...pageSignals.signals);
                    signals.push(...await this.checkLinkedAssetFingerprints(baseUrl, main.html, rawSignals, timeoutMs));
                }

                if (robots?.html) signals.push(...this.checkRobotsTxt(robots.html, rawSignals));
                if (sitemap?.html) signals.push(...this.checkSitemap(sitemap.html, rawSignals));

                // Smart file probes: skip if meta generator already gave high-conf answer,
                // else only probe top-3 CMS candidates from prior signals (full sweep if no candidates).
                const metaWin = signals.some(s => s.method === 'meta generator' && s.confidence >= 90);
                if (!metaWin) {
                    const tally: Record<string, number> = {};
                    for (const s of signals) {
                        if (s.category === 'CMS') tally[s.name] = Math.max(tally[s.name] ?? 0, s.confidence);
                    }
                    const candidates = Object.entries(tally)
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 3)
                        .map(([name]) => name);
                    signals.push(...await this.checkCmsFileProbes(baseUrl, rawSignals, candidates, timeoutMs));
                }
            }

        } catch (err) {
            this.logger.warn(`Detection failed for ${url}: ${String(err)}`);
        }

        const result = this.resolveResult(baseUrl, signals, rawSignals, serverTech, jsFrameworks, httpStatus, pageTitle, mainPage_result?.html ?? '', mainPage_result?.headers ?? {});

        // SPA-shell fallback: when nothing CMS-like matched but the page is a
        // bare SPA shell (root mount node + minimal body), label as SPA so the
        // UI shows something more useful than "Unknown".
        if (!result.cms && mainPage_result?.html) {
            const html = mainPage_result.html;
            const hasShell = /<div[^>]+id=["'](?:root|app|__next|__nuxt)["'][^>]*>\s*<\/div>/i.test(html)
                || /<div[^>]+id=["'](?:root|app)["'][^>]*>(?:\s|<!--[\s\S]*?-->)*<\/div>/i.test(html);
            if (hasShell || jsFrameworks.length > 0) {
                const cmsName = jsFrameworks[0] ?? 'SPA (Custom)';
                const method = hasShell ? 'SPA shell' : `JS framework: ${cmsName}`;
                result.cms = cmsName;
                result.confidence = jsFrameworks.length ? 55 : 45;
                result.category = 'Frontend Framework / SPA';
                result.detectionMethod = [...result.detectionMethod, method];
                result.evidence = [
                    ...result.evidence,
                    { name: cmsName, method, type: 'other', confidence: result.confidence, version: null, source: null },
                ];
                result.rawSignals['_evidence'] = JSON.stringify(result.evidence);
            }
        }

        // Cache only successful (non-empty) detections
        if (result.cms || serverTech.length || jsFrameworks.length) {
            this.detectCache.set(cacheKey, { result, exp: Date.now() + this.DETECT_TTL });
        }
        return result;
    }

    detectFromHtml(
        url: string,
        html: string,
        headers: Record<string, string> = {},
        status = 200,
    ): CmsDetectionResult {
        const baseUrl = this.normalizeUrl(url);
        const rawSignals: Record<string, string> = {};
        const normalizedHeaders = this.normalizeHeaders(headers);
        const pageSignals = this.collectHtmlSignals(baseUrl, html, normalizedHeaders, rawSignals);
        return this.resolveResult(
            baseUrl,
            pageSignals.signals,
            rawSignals,
            pageSignals.serverTech,
            pageSignals.jsFrameworks,
            status,
            pageSignals.pageTitle,
            html,
            normalizedHeaders,
        );
    }

    private collectHtmlSignals(
        baseUrl: string,
        html: string,
        headers: Record<string, string>,
        rawSignals: Record<string, string>,
    ): {
        signals: TechSignal[];
        serverTech: string[];
        jsFrameworks: string[];
        pageTitle: string | null;
    } {
        const signals: TechSignal[] = [];
        const serverTech = this.detectServerTech(headers, rawSignals);
        const jsFrameworks = this.detectJsFrameworks(html);

        const $ = cheerio.load(html);
        const rawTitle    = $('title').first().text().trim();
        const ogSiteName  = $('meta[property="og:site_name"]').attr('content')?.trim();
        const appName     = $('meta[name="application-name"]').attr('content')?.trim();
        const dcTitle     = $('meta[name="DC.title"]').attr('content')?.trim();
        const pageTitle = ogSiteName || appName || dcTitle || this.extractSiteName(rawTitle) || null;
        this.collectDefacementSignals($, html, rawSignals);

        signals.push(...this.checkPatternGroup(html, headers, this.CMS_PATTERNS, 'CMS', rawSignals));
        signals.push(...this.checkPatternGroup(html, headers, this.FRAMEWORK_PATTERNS, 'Backend Framework', rawSignals));
        signals.push(...this.checkPatternGroup(html, headers, this.HEADLESS_PATTERNS, 'Headless CMS', rawSignals));
        signals.push(...this.checkPatternGroup(html, headers, this.STATIC_PATTERNS, 'Static Site Generator (SSG)', rawSignals));
        signals.push(...this.checkMetaGenerator(html, rawSignals));
        signals.push(...this.checkJsCssVersions(html, rawSignals));
        signals.push(...this.checkHtmlComments(html, rawSignals));
        signals.push(...this.checkCookies(headers, rawSignals));
        signals.push(...this.checkInlineVersionPatterns(html, rawSignals));
        signals.push(...this.checkWappalyzerStyleFingerprints(baseUrl, html, headers, rawSignals, signals));

        return { signals, serverTech, jsFrameworks, pageTitle };
    }

    private collectDefacementSignals(
        $: ReturnType<typeof cheerio.load>,
        html: string,
        rawSignals: Record<string, string>,
    ) {
        const textDom = cheerio.load(html);
        textDom('script,style,noscript,template,svg,canvas').remove();

        const title = $('title').first().text().trim();
        const text = this.normalizeDefacementText(textDom('body').text() || textDom.root().text());
        const fallbackContent = this.normalizeDefacementText(
            html
                .replace(/<script[\s\S]*?<\/script>/gi, ' ')
                .replace(/<style[\s\S]*?<\/style>/gi, ' ')
                .replace(/<[^>]+>/g, ' '),
        );
        const content = (text || fallbackContent).slice(0, 250_000);

        const assetRefs = [
            ...$('img[src]').map((_, el) => this.normalizeAssetRef($(el).attr('src') || '')).get(),
            ...$('script[src]').map((_, el) => this.normalizeAssetRef($(el).attr('src') || '')).get(),
            ...$('link[href]').map((_, el) => this.normalizeAssetRef($(el).attr('href') || '')).get(),
        ].filter(Boolean).slice(0, 120);
        const headings = $('h1,h2,h3')
            .map((_, el) => this.normalizeDefacementText($(el).text()))
            .get()
            .filter(Boolean)
            .slice(0, 30);
        const structure = [
            `assets:${assetRefs.length}`,
            `forms:${$('form').length}`,
            `scripts:${$('script').length}`,
            `inputs:${$('input,textarea,select').length}`,
            `headings:${headings.join('|')}`,
            `refs:${assetRefs.join('|')}`,
        ].join('\n');

        const keywordText = `${title}\n${content.slice(0, 50_000)}`;
        const keywords: Array<[string, RegExp]> = [
            ['hacked by', /hacked\s+by/i],
            ['defaced', /\bdefaced\b/i],
            ['owned by', /\bowned\s+by\b/i],
            ['pwned', /\bpwned\b/i],
            ['cyber army', /\bcyber\s+army\b/i],
            ['hack team', /\bhack\s+team\b/i],
            ['security breached', /security\s+breach(?:ed)?/i],
            ['site hacked', /site\s+(?:has\s+been\s+)?hacked/i],
            ['index of hacked', /hacked\s+index/i],
        ];
        const hits = keywords
            .filter(([, pattern]) => pattern.test(keywordText))
            .map(([label]) => label);

        rawSignals['_deface_content_hash'] = this.sha256(content);
        rawSignals['_deface_structure_hash'] = this.sha256(structure);
        rawSignals['_deface_title_hash'] = title ? this.sha256(this.normalizeDefacementText(title)) : '';
        rawSignals['_deface_text_length'] = String(content.length);
        rawSignals['_deface_asset_count'] = String(assetRefs.length);
        rawSignals['_deface_form_count'] = String($('form').length);
        rawSignals['_deface_script_count'] = String($('script').length);
        rawSignals['_deface_keywords'] = hits.join(',');
    }

    private normalizeDefacementText(value: string): string {
        return value
            .replace(/\s+/g, ' ')
            .replace(/\b\d{1,2}:\d{2}(?::\d{2})?\b/g, '')
            .replace(/\b\d{4}-\d{2}-\d{2}\b/g, '')
            .replace(/\b\d{1,2}\.\d{1,2}\.\d{4}\b/g, '')
            .trim()
            .toLowerCase();
    }

    private normalizeAssetRef(value: string): string {
        const clean = value.trim();
        if (!clean) return '';
        try {
            const parsed = new URL(clean, 'https://local.invalid');
            return parsed.pathname.replace(/\/+/g, '/').toLowerCase();
        } catch {
            return clean.split(/[?#]/)[0].toLowerCase();
        }
    }

    private sha256(value: string): string {
        return createHash('sha256').update(value || '').digest('hex');
    }

    private checkWappalyzerStyleFingerprints(
        baseUrl: string,
        html: string,
        headers: Record<string, string>,
        raw: Record<string, string>,
        seedSignals: TechSignal[],
    ): TechSignal[] {
        const $ = cheerio.load(html);
        const bodyText = $('body').text();
        const scriptSrcs = $('script[src]').map((_, el) => $(el).attr('src') || '').get().filter(Boolean);
        const inlineScripts = $('script:not([src])').map((_, el) => $(el).text() || '').get().filter(Boolean);
        const meta = this.extractMetaMap($);
        const cookies = this.extractCookiePairs(headers['set-cookie'] || '');
        const pending: Array<{ name: string; requires?: string[]; excludes?: string[]; implies?: Array<{ name: string; confidence?: number }>; signals: TechSignal[] }> = [];

        for (const fp of WAPPALYZER_STYLE_FINGERPRINTS) {
            const localSignals: TechSignal[] = [];
            const category = fp.category as SiteCategory;
            const addMatches = (
                patterns: WappalyzerStylePattern[] | undefined,
                target: string,
                method: string,
                source?: string,
            ) => {
                if (!patterns?.length || !target) return;
                for (const pattern of patterns) {
                    const match = this.matchWappalyzerPattern(pattern, target);
                    if (!match) continue;
                    raw[`wappalyzer_${this.rawKeyPart(fp.name)}_${this.rawKeyPart(method)}_${localSignals.length + 1}`] =
                        `${source ? `${source}: ` : ''}${match.snippet}`;
                    localSignals.push({
                        name: fp.name,
                        version: match.version,
                        category,
                        confidence: match.confidence,
                        method,
                        source: source || undefined,
                    });
                }
            };

            addMatches(fp.html, html, 'Wappalyzer html');
            addMatches(fp.text, bodyText, 'Wappalyzer text');
            addMatches(fp.url, baseUrl, 'Wappalyzer url', baseUrl);

            for (const src of scriptSrcs) {
                addMatches(fp.scriptSrc, src, 'Wappalyzer scriptSrc', src);
            }
            for (const script of inlineScripts.slice(0, 12)) {
                addMatches(fp.scripts, script.slice(0, 250_000), 'Wappalyzer scripts');
            }

            for (const [headerName, patterns] of Object.entries(fp.headers || {})) {
                addMatches(patterns, headers[headerName.toLowerCase()] || '', `Wappalyzer header: ${headerName}`, headerName);
            }

            for (const [metaName, patterns] of Object.entries(fp.meta || {})) {
                addMatches(patterns, meta[metaName.toLowerCase()] || '', `Wappalyzer meta: ${metaName}`, metaName);
            }

            for (const [cookieName, patterns] of Object.entries(fp.cookies || {})) {
                const cookie = cookies.find(item => item.name.toLowerCase().startsWith(cookieName.toLowerCase()));
                addMatches(patterns, cookie?.value || '', `Wappalyzer cookie: ${cookieName}`, cookie?.name);
            }

            for (const rule of fp.dom || []) {
                try {
                    const nodes = $(rule.selector);
                    if (!nodes.length) continue;
                    localSignals.push({
                        name: fp.name,
                        version: null,
                        category,
                        confidence: rule.confidence ?? 80,
                        method: `Wappalyzer dom: ${rule.selector}`,
                        source: rule.selector,
                    });
                    raw[`wappalyzer_${this.rawKeyPart(fp.name)}_dom_${localSignals.length}`] = rule.selector;

                    const text = nodes.first().text();
                    addMatches(rule.text, text, `Wappalyzer dom text: ${rule.selector}`, rule.selector);

                    for (const [attr, patterns] of Object.entries(rule.attributes || {})) {
                        const value = nodes.first().attr(attr) || '';
                        addMatches(patterns, value, `Wappalyzer dom attr: ${rule.selector}[${attr}]`, `${rule.selector}[${attr}]`);
                    }
                } catch { /* invalid selector in a local fingerprint should not break detection */ }
            }

            if (localSignals.length) {
                pending.push({
                    name: fp.name,
                    requires: fp.requires,
                    excludes: fp.excludes,
                    implies: fp.implies,
                    signals: localSignals,
                });
            }
        }

        const matchedNames = new Set([
            ...seedSignals.map(signal => signal.name),
            ...pending.map(item => item.name),
        ]);
        const output: TechSignal[] = [];

        for (const item of pending) {
            if (item.requires?.some(required => !matchedNames.has(required))) continue;
            if (item.excludes?.some(excluded => matchedNames.has(excluded))) continue;

            output.push(...item.signals);

            for (const implied of item.implies || []) {
                if (matchedNames.has(implied.name)) continue;
                matchedNames.add(implied.name);
                output.push({
                    name: implied.name,
                    version: null,
                    category: this.CMS_CATEGORY_MAP[implied.name] ?? 'Backend Framework',
                    confidence: implied.confidence ?? 50,
                    method: `Wappalyzer implies: ${item.name}`,
                    source: item.name,
                });
            }
        }

        return output;
    }

    private matchWappalyzerPattern(
        pattern: WappalyzerStylePattern,
        target: string,
    ): { confidence: number; version: string | null; snippet: string } | null {
        pattern.regex.lastIndex = 0;
        const match = target.match(pattern.regex);
        if (!match) return null;

        const version = pattern.version
            ? pattern.version.replace(/\\(\d+)/g, (_, idx) => match[Number(idx)] || '').trim() || null
            : null;
        const index = Math.max(0, match.index ?? 0);
        return {
            confidence: pattern.confidence ?? 85,
            version,
            snippet: target.slice(index, index + 140),
        };
    }

    private extractMetaMap($: ReturnType<typeof cheerio.load>): Record<string, string> {
        const meta: Record<string, string> = {};
        $('meta').each((_, el) => {
            const key = ($(el).attr('name') || $(el).attr('property') || $(el).attr('http-equiv') || '').toLowerCase();
            const value = $(el).attr('content') || '';
            if (key && value) meta[key] = value;
        });
        return meta;
    }

    private extractCookiePairs(setCookie: string): Array<{ name: string; value: string }> {
        const cookies: Array<{ name: string; value: string }> = [];
        const re = /(?:^|[,;]\s*)([A-Za-z0-9_.-]+)=([^;,]*)/g;
        let match: RegExpExecArray | null;
        while ((match = re.exec(setCookie)) !== null) {
            const name = match[1];
            if (/^(path|expires|max-age|domain|samesite|secure|httponly)$/i.test(name)) continue;
            cookies.push({ name, value: match[2] || 'present' });
        }
        return cookies;
    }

    private rawKeyPart(value: string): string {
        return value.replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '').slice(0, 60).toLowerCase();
    }

    // ── HTML COMMENT PARSING ──────────────────────────────────────────────────
    private checkHtmlComments(html: string, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];
        const comments = html.match(/<!--[\s\S]*?-->/g) || [];

        for (const comment of comments.slice(0, 30)) {
            const checks: Array<{ re: RegExp; name: string; category: SiteCategory; verRe?: RegExp }> = [
                { re: /wordpress/i, name: 'WordPress', category: 'CMS', verRe: /wordpress\s*([\d.]+)/i },
                { re: /wp-content/i, name: 'WordPress', category: 'CMS' },
                { re: /joomla/i, name: 'Joomla', category: 'CMS', verRe: /joomla\s*([\d.]+)/i },
                { re: /drupal/i, name: 'Drupal', category: 'CMS', verRe: /drupal\s*([\d.]+)/i },
                { re: /bitrix/i, name: 'Bitrix', category: 'CMS' },
                { re: /modx/i, name: 'MODX', category: 'CMS', verRe: /modx\s*([\d.]+)/i },
                { re: /typo3/i, name: 'TYPO3', category: 'CMS', verRe: /typo3\s*([\d.]+)/i },
                { re: /umbraco/i, name: 'Umbraco', category: 'CMS', verRe: /umbraco\s*([\d.]+)/i },
                { re: /kentico|xperience/i, name: 'Kentico Xperience', category: 'CMS', verRe: /(?:kentico|xperience)\s*([\d.]+)/i },
                { re: /sitecore/i, name: 'Sitecore', category: 'CMS', verRe: /sitecore\s*([\d.]+)/i },
                { re: /adobe experience manager|\baem\b/i, name: 'Adobe Experience Manager', category: 'CMS' },
                { re: /liferay/i, name: 'Liferay', category: 'CMS', verRe: /liferay\s*([\d.]+)/i },
                { re: /hubspot/i, name: 'HubSpot CMS', category: 'CRM / ERP Web System' },
                { re: /craft cms|craftcms/i, name: 'Craft CMS', category: 'CMS', verRe: /craft cms\s*([\d.]+)/i },
            ];

            for (const { re, name, category, verRe } of checks) {
                if (re.test(comment)) {
                    const version = verRe ? (comment.match(verRe)?.[1] || null) : null;
                    raw[`comment_${name}`] = comment.slice(0, 100);
                    signals.push({ name, version, category, confidence: 65, method: 'HTML comment' });
                    break;
                }
            }
        }
        return signals;
    }

    // ── COOKIE DETECTION ──────────────────────────────────────────────────────
    private checkCookies(headers: Record<string, string>, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];
        const setCookie = headers['set-cookie'] || '';
        if (!setCookie) return signals;

        raw['set_cookie'] = setCookie.slice(0, 200);

        const cookieMap: Array<{ re: RegExp; name: string; category: SiteCategory; confidence: number }> = [
            { re: /wordpress_/i, name: 'WordPress', category: 'CMS', confidence: 85 },
            { re: /wp-settings/i, name: 'WordPress', category: 'CMS', confidence: 85 },
            { re: /BITRIX_SM_/i, name: 'Bitrix', category: 'CMS', confidence: 88 },
            { re: /BX_USER_ID/i, name: 'Bitrix', category: 'CMS', confidence: 80 },
            { re: /joomla_user_state/i, name: 'Joomla', category: 'CMS', confidence: 85 },
            { re: /SESS[a-f0-9]{16}/i, name: 'Drupal', category: 'CMS', confidence: 80 },
            { re: /fe_typo_user/i, name: 'TYPO3', category: 'CMS', confidence: 88 },
            { re: /be_typo_user/i, name: 'TYPO3', category: 'CMS', confidence: 88 },
            { re: /laravel_session/i, name: 'Laravel', category: 'Backend Framework', confidence: 85 },
            { re: /XSRF-TOKEN/i, name: 'Laravel', category: 'Backend Framework', confidence: 70 },
            { re: /_shopify_/i, name: 'Shopify', category: 'CMS', confidence: 92 },
            { re: /PrestaShop/i, name: 'PrestaShop', category: 'CMS', confidence: 85 },
            { re: /ss_cvr/i, name: 'Squarespace', category: 'CMS', confidence: 85 },
            { re: /_csrf-frontend|_csrf-backend|_identity-frontend|_identity-backend/i, name: 'Yii2', category: 'Backend Framework', confidence: 90 },
            { re: /_csrf=[a-f0-9]+%3A2%3A%7Bi%3A0%3Bs%3A5%3A%22_csrf%22/i, name: 'Yii2', category: 'Backend Framework', confidence: 92 },
            { re: /OCSESSID/i, name: 'OpenCart', category: 'CMS', confidence: 85 },
            { re: /ci_session/i, name: 'CodeIgniter', category: 'Backend Framework', confidence: 85 },
            { re: /symfony/i, name: 'Symfony', category: 'Backend Framework', confidence: 80 },
            { re: /\.AspNetCore\.(Antiforgery|Cookies|Identity|Session|Mvc)/i, name: 'ASP.NET Core', category: 'Backend Framework', confidence: 92 },
            { re: /ASP\.NET_SessionId/i, name: 'ASP.NET', category: 'Backend Framework', confidence: 90 },
            { re: /CraftSessionId|CRAFT_CSRF_TOKEN/i, name: 'Craft CMS', category: 'CMS', confidence: 88 },
            { re: /CONCRETE5|ccmUserHash/i, name: 'Concrete CMS', category: 'CMS', confidence: 88 },
            { re: /PastMember|SilverStripe/i, name: 'SilverStripe', category: 'CMS', confidence: 84 },
            { re: /UMB_UCONTEXT|UMB-XSRF|UMB_PREVIEW/i, name: 'Umbraco', category: 'CMS', confidence: 90 },
            { re: /CMSPreferredCulture|CMSCsrfCookie|CMSCurrentTheme|CMSCookieLevel/i, name: 'Kentico Xperience', category: 'CMS', confidence: 88 },
            { re: /SC_ANALYTICS_GLOBAL_COOKIE|sitecore/i, name: 'Sitecore', category: 'CMS', confidence: 88 },
            { re: /GUEST_LANGUAGE_ID|LFR_SESSION_STATE|COMPANY_ID/i, name: 'Liferay', category: 'CMS', confidence: 85 },
            { re: /\.DOTNETNUKE|dnn_IsMobile/i, name: 'DNN', category: 'CMS', confidence: 88 },
            { re: /FedAuth|rtFa/i, name: 'SharePoint', category: 'CMS', confidence: 76 },
            { re: /hubspotutk|__hstc|__hssc/i, name: 'HubSpot CMS', category: 'CRM / ERP Web System', confidence: 88 },
            { re: /txp_login/i, name: 'Textpattern', category: 'CMS', confidence: 82 },
            { re: /exp_tracker|exp_last_visit/i, name: 'ExpressionEngine', category: 'CMS', confidence: 82 },
        ];

        for (const { re, name, category, confidence } of cookieMap) {
            if (re.test(setCookie)) {
                signals.push({ name, version: null, category, confidence, method: 'Cookie' });
            }
        }
        return signals;
    }

    // ── INLINE VERSION PATTERNS ───────────────────────────────────────────────
    private checkInlineVersionPatterns(html: string, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];

        const checks: Array<{ re: RegExp; name: string; category: SiteCategory; verIdx: number }> = [
            // WordPress
            { re: /wordpress\.org\/\?v=([\d.]+)/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            { re: /wp-emoji-release\.min\.js\?ver=([\d.]+)/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            { re: /wp-includes\/js\/[^"']*\?ver=([\d.]+)/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            { re: /var\s+_wpVersion\s*=\s*['"]([^'"]+)['"]/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            { re: /"version":"([\d.]+)"[^}]*"name":"WordPress"/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            { re: /<meta[^>]+generator[^>]+WordPress\s+([\d.]+)/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            // Bitrix
            { re: /BX\.message\([^)]*"version"\s*:\s*"([\d.]+)"/i, name: 'Bitrix', category: 'CMS', verIdx: 1 },
            { re: /1C-Bitrix[^;]*;\s*v\.([\d.]+)/i, name: 'Bitrix', category: 'CMS', verIdx: 1 },
            // Joomla
            { re: /Joomla!\s*([\d.]+)/i, name: 'Joomla', category: 'CMS', verIdx: 1 },
            { re: /joomla[^"']*['"]([\d]+\.[.\d]+)['"]/i, name: 'Joomla', category: 'CMS', verIdx: 1 },
            // Ghost
            { re: /Ghost\s+v?([\d.]+)/i, name: 'Ghost', category: 'CMS', verIdx: 1 },
            // TYPO3
            { re: /typo3\/js\/[^'"]*\?[^'"]*v=([\d.]+)/i, name: 'TYPO3', category: 'CMS', verIdx: 1 },
            { re: /TYPO3\s+CMS\s+([\d.]+)/i, name: 'TYPO3', category: 'CMS', verIdx: 1 },
            // Django
            { re: /"django":\s*"([\d.]+)"/i, name: 'Django', category: 'Backend Framework', verIdx: 1 },
            // MODX
            { re: /MODX\s+Revolution\s+([\d.]+(?:-[a-z]+[\d]*)?)/i, name: 'MODX', category: 'CMS', verIdx: 1 },
            // DLE
            { re: /DataLife Engine\s*v?\s*([\d.]+)/i, name: 'DLE', category: 'CMS', verIdx: 1 },
            // PrestaShop
            { re: /prestashop[^"']*['"]([\d]+\.[.\d]+)['"]/i, name: 'PrestaShop', category: 'CMS', verIdx: 1 },
            // Magento
            { re: /Magento\/([\d.]+)/i, name: 'Magento', category: 'CMS', verIdx: 1 },
            { re: /Mage\.VERSION\s*=\s*['"]([^'"]+)['"]/i, name: 'Magento', category: 'CMS', verIdx: 1 },
            // Hugo
            { re: /Hugo\s+([\d.]+)/i, name: 'Hugo', category: 'Static Site Generator (SSG)', verIdx: 1 },
            // Next.js
            { re: /"next"\s*:\s*\{\s*"version"\s*:\s*"([\d.]+)"/i, name: 'Next.js', category: 'Fullstack Framework', verIdx: 1 },
        ];

        for (const { re, name, category, verIdx } of checks) {
            const match = html.match(re);
            if (match?.[verIdx]) {
                raw[`inline_${name}`] = match[0].slice(0, 100);
                signals.push({ name, version: match[verIdx], category, confidence: 90, method: 'Inline version' });
            }
        }
        return signals;
    }

    // ── ROBOTS.TXT ───────────────────────────────────────────────────────────
    private checkRobotsTxt(body: string, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];
        raw['robots_txt'] = body.slice(0, 300);

        const checks: Array<{ pattern: RegExp; name: string; category: SiteCategory }> = [
            { pattern: /\/wp-admin/i, name: 'WordPress', category: 'CMS' },
            { pattern: /\/wp-content/i, name: 'WordPress', category: 'CMS' },
            { pattern: /\/bitrix\//i, name: 'Bitrix', category: 'CMS' },
            { pattern: /\/administrator\//i, name: 'Joomla', category: 'CMS' },
            { pattern: /\/user\/login/i, name: 'Drupal', category: 'CMS' },
            { pattern: /\/sites\/default\//i, name: 'Drupal', category: 'CMS' },
            { pattern: /opencart/i, name: 'OpenCart', category: 'CMS' },
            { pattern: /\/typo3\//i, name: 'TYPO3', category: 'CMS' },
            { pattern: /\/manager\//i, name: 'MODX', category: 'CMS' },
            { pattern: /opencart/i, name: 'OpenCart', category: 'CMS' },
            { pattern: /prestashop/i, name: 'PrestaShop', category: 'CMS' },
            { pattern: /\/design\/themes\//i, name: 'CS-Cart', category: 'CMS' },
            { pattern: /\/engine\/classes\//i, name: 'DLE', category: 'CMS' },
            { pattern: /\/umbraco\//i, name: 'Umbraco', category: 'CMS' },
            { pattern: /\/CMSPages\//i, name: 'Kentico Xperience', category: 'CMS' },
            { pattern: /\/sitecore\//i, name: 'Sitecore', category: 'CMS' },
            { pattern: /\/etc\.clientlibs\//i, name: 'Adobe Experience Manager', category: 'CMS' },
            { pattern: /\/DesktopModules\//i, name: 'DNN', category: 'CMS' },
            { pattern: /\/_layouts\/15\//i, name: 'SharePoint', category: 'CMS' },
            { pattern: /\/o\/classic-theme\//i, name: 'Liferay', category: 'CMS' },
        ];

        for (const { pattern, name, category } of checks) {
            if (pattern.test(body)) {
                signals.push({ name, version: null, category, confidence: 70, method: 'robots.txt' });
            }
        }
        // SPA-served HTML at /robots.txt
        if (/__NEXT_DATA__|\/_next\/static\//i.test(body))
            signals.push({ name: 'Next.js', version: null, category: 'Fullstack Framework', confidence: 80, method: 'robots.txt (SPA)' });
        if (/__NUXT__|\/_nuxt\//i.test(body))
            signals.push({ name: 'Nuxt.js', version: null, category: 'Fullstack Framework', confidence: 80, method: 'robots.txt (SPA)' });
        return signals;
    }

    // ── SITEMAP ───────────────────────────────────────────────────────────────
    private checkSitemap(body: string, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];
        raw['sitemap'] = body.slice(0, 300);

        if (/\/wp-content\//i.test(body) || /yoast/i.test(body) || /wordpress/i.test(body))
            signals.push({ name: 'WordPress', version: null, category: 'CMS', confidence: 75, method: 'sitemap.xml' });
        if (/\/bitrix\//i.test(body))
            signals.push({ name: 'Bitrix', version: null, category: 'CMS', confidence: 75, method: 'sitemap.xml' });
        if (/\/components\/com_/i.test(body))
            signals.push({ name: 'Joomla', version: null, category: 'CMS', confidence: 70, method: 'sitemap.xml' });
        if (/\/sites\/default\//i.test(body))
            signals.push({ name: 'Drupal', version: null, category: 'CMS', confidence: 70, method: 'sitemap.xml' });
        if (/\/umbraco\/|DependencyHandler\.axd/i.test(body))
            signals.push({ name: 'Umbraco', version: null, category: 'CMS', confidence: 72, method: 'sitemap.xml' });
        if (/\/CMSPages\/|\/getmedia\//i.test(body))
            signals.push({ name: 'Kentico Xperience', version: null, category: 'CMS', confidence: 72, method: 'sitemap.xml' });
        if (/\/sitecore\/|\/-\/media\//i.test(body))
            signals.push({ name: 'Sitecore', version: null, category: 'CMS', confidence: 72, method: 'sitemap.xml' });
        if (/\/etc\.clientlibs\/|\/content\/dam\//i.test(body))
            signals.push({ name: 'Adobe Experience Manager', version: null, category: 'CMS', confidence: 72, method: 'sitemap.xml' });
        if (/\/DesktopModules\/|\/Portals\/_default\//i.test(body))
            signals.push({ name: 'DNN', version: null, category: 'CMS', confidence: 72, method: 'sitemap.xml' });
        if (/hs-scripts\.com|hubspot/i.test(body))
            signals.push({ name: 'HubSpot CMS', version: null, category: 'CRM / ERP Web System', confidence: 72, method: 'sitemap.xml' });
        // SPA-served HTML at /sitemap.xml: hint at framework
        if (/__NEXT_DATA__|\/_next\/static\//i.test(body))
            signals.push({ name: 'Next.js', version: null, category: 'Fullstack Framework', confidence: 80, method: 'sitemap.xml (SPA)' });
        if (/__NUXT__|\/_nuxt\//i.test(body))
            signals.push({ name: 'Nuxt.js', version: null, category: 'Fullstack Framework', confidence: 80, method: 'sitemap.xml (SPA)' });
        if (/ng-version=/i.test(body))
            signals.push({ name: 'Angular', version: null, category: 'Frontend Framework / SPA', confidence: 75, method: 'sitemap.xml (SPA)' });

        return signals;
    }

    // ── JS/CSS VERSION ────────────────────────────────────────────────────────
    private checkJsCssVersions(html: string, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];
        const $ = cheerio.load(html);

        $('script[src], link[rel="stylesheet"][href]').each((_, el) => {
            const src = $(el).attr('src') || $(el).attr('href') || '';
            if (!src) return;

            if (/\/wp-(includes|content)\//.test(src)) {
                const ver = src.match(/[?&]ver=([\d.]+)/)?.[1];
                if (ver) { raw['wp_asset_ver'] = src.slice(0, 120); signals.push({ name: 'WordPress', version: ver, category: 'CMS', confidence: 88, method: 'Asset ?ver=' }); }
                else signals.push({ name: 'WordPress', version: null, category: 'CMS', confidence: 80, method: 'WP asset path' });
            }
            if (/\/bitrix\//.test(src)) {
                const ver = src.match(/[?&]v=([\d.]+)/)?.[1];
                raw['bitrix_asset'] = src.slice(0, 120);
                signals.push({ name: 'Bitrix', version: ver || null, category: 'CMS', confidence: 85, method: 'Bitrix asset path' });
            }
            if (/\/media\/jui\//.test(src) || /\/media\/system\//.test(src)) {
                const ver = src.match(/[?&]v=([\d.]+)/)?.[1];
                signals.push({ name: 'Joomla', version: ver || null, category: 'CMS', confidence: 85, method: 'Joomla asset path' });
            }
            if (/\/sites\/(all|default)\//.test(src)) {
                signals.push({ name: 'Drupal', version: null, category: 'CMS', confidence: 82, method: 'Drupal asset path' });
            }
            if (/\/typo3\//.test(src)) {
                signals.push({ name: 'TYPO3', version: null, category: 'CMS', confidence: 82, method: 'TYPO3 asset path' });
            }
            if (/\/assets\/components\//.test(src)) {
                signals.push({ name: 'MODX', version: null, category: 'CMS', confidence: 80, method: 'MODX asset path' });
            }
            if (/\/cpresources\//i.test(src)) {
                signals.push({ name: 'Craft CMS', version: null, category: 'CMS', confidence: 82, method: 'Craft asset path' });
            }
            if (/\/concrete\/(js|css)\//i.test(src)) {
                signals.push({ name: 'Concrete CMS', version: null, category: 'CMS', confidence: 82, method: 'Concrete asset path' });
            }
            if (/\/umbraco(_client)?\//i.test(src) || /DependencyHandler\.axd/i.test(src)) {
                signals.push({ name: 'Umbraco', version: null, category: 'CMS', confidence: 84, method: 'Umbraco asset path' });
            }
            if (/\/CMSPages\/|\/CMSScripts\/|\/CMSPages\/GetResource\.ashx|\/getmedia\//i.test(src)) {
                signals.push({ name: 'Kentico Xperience', version: null, category: 'CMS', confidence: 84, method: 'Kentico asset path' });
            }
            if (/\/sitecore\/|\/layouts\/system\/|\/-\/media\//i.test(src)) {
                signals.push({ name: 'Sitecore', version: null, category: 'CMS', confidence: 84, method: 'Sitecore asset path' });
            }
            if (/\/etc\.clientlibs\/|\/content\/dam\/|\/libs\/granite\//i.test(src)) {
                signals.push({ name: 'Adobe Experience Manager', version: null, category: 'CMS', confidence: 84, method: 'AEM asset path' });
            }
            if (/\/o\/frontend-|\/o\/classic-theme\//i.test(src)) {
                signals.push({ name: 'Liferay', version: null, category: 'CMS', confidence: 82, method: 'Liferay asset path' });
            }
            if (/\/DesktopModules\/|\/Portals\/_default\//i.test(src)) {
                signals.push({ name: 'DNN', version: null, category: 'CMS', confidence: 82, method: 'DNN asset path' });
            }
            if (/\/_layouts\/15\/|\/_catalogs\/|\/_vti_bin\//i.test(src)) {
                signals.push({ name: 'SharePoint', version: null, category: 'CMS', confidence: 84, method: 'SharePoint asset path' });
            }
            if (/hs-scripts\.com|hsforms\.net|js\.hsforms\.net/i.test(src)) {
                signals.push({ name: 'HubSpot CMS', version: null, category: 'CRM / ERP Web System', confidence: 86, method: 'HubSpot asset path' });
            }
            if (/cdn2\.editmysite\.com|weebly\.com/i.test(src)) {
                signals.push({ name: 'Weebly', version: null, category: 'Web Builder / No-Code Platform', confidence: 82, method: 'Weebly asset path' });
            }
            if (/static-cdn\.multiscreensite\.com/i.test(src)) {
                signals.push({ name: 'Duda', version: null, category: 'Web Builder / No-Code Platform', confidence: 82, method: 'Duda asset path' });
            }
            if (/framerusercontent\.com|data-framer-/i.test(src)) {
                signals.push({ name: 'Framer', version: null, category: 'Web Builder / No-Code Platform', confidence: 80, method: 'Framer asset path' });
            }
        });

        return signals;
    }

    private async checkLinkedAssetFingerprints(
        baseUrl: string,
        html: string,
        raw: Record<string, string>,
        timeoutMs = 20_000,
    ): Promise<TechSignal[]> {
        const signals: TechSignal[] = [];
        const urls = this.extractInspectableAssetUrls(baseUrl, html);
        if (!urls.length) return signals;

        const settled = await Promise.allSettled(
            urls.map(async assetUrl => ({ assetUrl, page: await this.fetchPage(assetUrl, 0, Math.min(timeoutMs, 8_000)) })),
        );

        for (const item of settled) {
            if (item.status !== 'fulfilled' || !item.value.page || item.value.page.status >= 400) continue;
            const assetUrl = item.value.assetUrl;
            const body = item.value.page.html.slice(0, 500_000);

            for (const fp of JS_BUNDLE_FINGERPRINTS) {
                if (!fp.patterns.some(pattern => pattern.test(body))) continue;

                const version = fp.versionPattern ? (body.match(fp.versionPattern)?.[1] ?? null) : null;
                const source = this.compactAssetName(assetUrl);
                raw[`bundle_${fp.name}_${source}`] = this.firstMatchingSnippet(body, fp.patterns) ?? source;
                signals.push({
                    name: fp.name,
                    version,
                    category: fp.category as SiteCategory,
                    confidence: fp.confidence,
                    method: `JS bundle: ${source}`,
                    source,
                });
            }
        }

        return signals;
    }

    private extractInspectableAssetUrls(baseUrl: string, html: string): string[] {
        const $ = cheerio.load(html);
        const base = new URL(baseUrl);
        const urls = new Set<string>();

        $('script[src], link[rel="modulepreload"][href]').each((_, el) => {
            const raw = $(el).attr('src') || $(el).attr('href') || '';
            if (!raw || raw.startsWith('data:')) return;

            try {
                const url = new URL(raw, baseUrl);
                if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
                if (url.origin !== base.origin && !this.isKnownInspectableAssetHost(url.hostname)) return;
                if (!/\.m?js(?:$|[?#])|\/_next\/static\/|\/_nuxt\/|\/assets\//i.test(url.pathname)) return;
                urls.add(url.toString());
            } catch { /* ignore malformed asset URLs */ }
        });

        return Array.from(urls).slice(0, 6);
    }

    private isKnownInspectableAssetHost(hostname: string): boolean {
        return /(^|\.)((shopifycdn|contentful|storyblok|hygraph|graphcms|directus)\.com|sanity\.io|ctfassets\.net)$/i.test(hostname);
    }

    private compactAssetName(assetUrl: string): string {
        try {
            const url = new URL(assetUrl);
            const parts = url.pathname.split('/').filter(Boolean);
            return parts.slice(-2).join('/') || url.hostname;
        } catch {
            return assetUrl.slice(0, 80);
        }
    }

    private firstMatchingSnippet(body: string, patterns: RegExp[]): string | null {
        for (const pattern of patterns) {
            const match = body.match(pattern);
            if (!match) continue;
            const index = Math.max(0, match.index ?? 0);
            return body.slice(index, index + 140);
        }
        return null;
    }

    // ── META GENERATOR ────────────────────────────────────────────────────────
    private checkMetaGenerator(html: string, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];
        const $ = cheerio.load(html);
        const generator = $('meta[name="generator"]').attr('content') || '';
        if (!generator) return signals;
        raw['meta_generator'] = generator;

        const matchers: Array<{ pattern: RegExp; name: string; category: SiteCategory }> = [
            { pattern: /WordPress\s*([\d.]*)/i, name: 'WordPress', category: 'CMS' },
            { pattern: /Joomla!\s*([\d.]*)/i, name: 'Joomla', category: 'CMS' },
            { pattern: /Drupal\s*([\d.]*)/i, name: 'Drupal', category: 'CMS' },
            { pattern: /1C-Bitrix\s*([\d.]*)/i, name: 'Bitrix', category: 'CMS' },
            { pattern: /MODX\s*([\d.]*)/i, name: 'MODX', category: 'CMS' },
            { pattern: /Wix\.com/i, name: 'Wix', category: 'CMS' },
            { pattern: /Ghost\s*([\d.]*)/i, name: 'Ghost', category: 'CMS' },
            { pattern: /TYPO3\s*([\d.]*)/i, name: 'TYPO3', category: 'CMS' },
            { pattern: /OpenCart\s*([\d.]*)/i, name: 'OpenCart', category: 'CMS' },
            { pattern: /PrestaShop\s*([\d.]*)/i, name: 'PrestaShop', category: 'CMS' },
            { pattern: /Hugo\s*([\d.]*)/i, name: 'Hugo', category: 'Static Site Generator (SSG)' },
            { pattern: /Jekyll\s*([\d.]*)/i, name: 'Jekyll', category: 'Static Site Generator (SSG)' },
            { pattern: /Gatsby\s*([\d.]*)/i, name: 'Gatsby', category: 'Static Site Generator (SSG)' },
            { pattern: /Next\.js\s*([\d.]*)/i, name: 'Next.js', category: 'Fullstack Framework' },
            { pattern: /Nuxt\s*([\d.]*)/i, name: 'Nuxt.js', category: 'Fullstack Framework' },
            { pattern: /Astro\s*([\d.]*)/i, name: 'Astro', category: 'Fullstack Framework' },
            { pattern: /October\s*([\d.]*)/i, name: 'OctoberCMS', category: 'CMS' },
            { pattern: /OpenCart\s*([\d.]*)/i, name: 'OpenCart', category: 'CMS' },
            { pattern: /PrestaShop\s*([\d.]*)/i, name: 'PrestaShop', category: 'CMS' },
            { pattern: /Magento\s*([\d.]*)/i, name: 'Magento', category: 'CMS' },
            { pattern: /CS-Cart\s*([\d.]*)/i, name: 'CS-Cart', category: 'CMS' },
            { pattern: /DataLife Engine\s*([\d.]*)/i, name: 'DLE', category: 'CMS' },
            { pattern: /UMI\.CMS\s*([\d.]*)/i, name: 'UMI.CMS', category: 'CMS' },
            { pattern: /Craft CMS\s*([\d.]*)/i, name: 'Craft CMS', category: 'CMS' },
            { pattern: /Concrete(?:5| CMS)?\s*([\d.]*)/i, name: 'Concrete CMS', category: 'CMS' },
            { pattern: /SilverStripe\s*([\d.]*)/i, name: 'SilverStripe', category: 'CMS' },
            { pattern: /Umbraco\s*([\d.]*)/i, name: 'Umbraco', category: 'CMS' },
            { pattern: /Kentico\s*([\d.]*)/i, name: 'Kentico Xperience', category: 'CMS' },
            { pattern: /Xperience\s*([\d.]*)/i, name: 'Kentico Xperience', category: 'CMS' },
            { pattern: /Sitecore\s*([\d.]*)/i, name: 'Sitecore', category: 'CMS' },
            { pattern: /Adobe Experience Manager\s*([\d.]*)/i, name: 'Adobe Experience Manager', category: 'CMS' },
            { pattern: /Liferay\s*([\d.]*)/i, name: 'Liferay', category: 'CMS' },
            { pattern: /DotNetNuke\s*([\d.]*)/i, name: 'DNN', category: 'CMS' },
            { pattern: /\bDNN\s*([\d.]*)/i, name: 'DNN', category: 'CMS' },
            { pattern: /Orchard Core\s*([\d.]*)/i, name: 'Orchard Core', category: 'CMS' },
            { pattern: /Microsoft SharePoint\s*([\d.]*)/i, name: 'SharePoint', category: 'CMS' },
            { pattern: /Plone\s*([\d.]*)/i, name: 'Plone', category: 'CMS' },
            { pattern: /HubSpot\s*([\d.]*)/i, name: 'HubSpot CMS', category: 'CRM / ERP Web System' },
            { pattern: /Blogger\s*([\d.]*)/i, name: 'Blogger', category: 'Blog Engine' },
            { pattern: /Weebly\s*([\d.]*)/i, name: 'Weebly', category: 'Web Builder / No-Code Platform' },
            { pattern: /Duda\s*([\d.]*)/i, name: 'Duda', category: 'Web Builder / No-Code Platform' },
            { pattern: /Framer\s*([\d.]*)/i, name: 'Framer', category: 'Web Builder / No-Code Platform' },
            { pattern: /Textpattern\s*([\d.]*)/i, name: 'Textpattern', category: 'CMS' },
            { pattern: /ExpressionEngine\s*([\d.]*)/i, name: 'ExpressionEngine', category: 'CMS' },
            { pattern: /Statamic\s*([\d.]*)/i, name: 'Statamic', category: 'CMS' },
        ];

        for (const { pattern, name, category } of matchers) {
            const match = generator.match(pattern);
            if (match) {
                signals.push({ name, version: match[1]?.trim() || null, category, confidence: 95, method: 'meta generator' });
            }
        }
        return signals;
    }

    // ── UNIVERSAL PATTERN CHECKER ─────────────────────────────────────────────
    private checkPatternGroup(
        html: string, headers: Record<string, string>,
        group: Array<{
            name: string; patterns: RegExp[];
            headerKeys?: Array<{ key: string; pattern: RegExp; versionPattern?: RegExp }>;
            versionPatterns?: RegExp[];
            cookieKeys?: RegExp[];
        }>,
        category: SiteCategory, raw: Record<string, string>,
    ): TechSignal[] {
        const signals: TechSignal[] = [];

        for (const tech of group) {
            let matchCount = 0;
            let htmlMatchCount = 0;
            let headerMatchCount = 0;
            let version: string | null = null;

            for (const pattern of tech.patterns || []) {
                if (pattern.test(html)) {
                    matchCount++;
                    htmlMatchCount++;
                    raw[`html_${tech.name}_${matchCount}`] = pattern.toString();
                }
            }

            for (const hk of tech.headerKeys || []) {
                const val = headers[hk.key.toLowerCase()] || '';
                if (hk.pattern.test(val)) {
                    matchCount++;
                    headerMatchCount++;
                    raw[`header_${tech.name}`] = val;
                    if (hk.versionPattern) {
                        const m = val.match(hk.versionPattern);
                        if (m?.[1]) version = m[1];
                    }
                }
            }

            // versionPatterns dan versiyani qidiramiz
            if (!version && tech.versionPatterns) {
                for (const vp of tech.versionPatterns) {
                    const m = html.match(vp);
                    if (m?.[1]) { version = m[1]; break; }
                }
            }

            if (matchCount > 0) {
                // HTML patterns alone = "soft" evidence; base starts low
                const baseConf = category === 'CMS' ? 50 : 42;
                const bonus = Math.min(matchCount - 1, 4) * 4;  // +4 per extra match, max +16
                const methodParts = [
                    htmlMatchCount ? `Pattern (${htmlMatchCount} match)` : '',
                    headerMatchCount ? `Header (${headerMatchCount} match)` : '',
                ].filter(Boolean);
                signals.push({
                    name: tech.name, version, category,
                    confidence: baseConf + bonus,
                    method: methodParts.join(' + '),
                });
            }
        }
        return signals;
    }

    // ── FILE PROBES ───────────────────────────────────────────────────────────
    private async checkCmsFileProbes(
        baseUrl: string,
        raw: Record<string, string>,
        candidates?: string[],
        timeoutMs = 20_000,
    ): Promise<TechSignal[]> {
        const cmsList = candidates && candidates.length
            ? this.CMS_PATTERNS.filter(c => candidates.includes(c.name))
            : this.CMS_PATTERNS;
        const probes: Array<{
            path: string;
            name: string;
            category: SiteCategory;
            confidence: number;
            allowErrorStatus?: boolean;
            extractor: (b: string, status: number, headers: Record<string, string>) => string | null;
        }> = [];
        for (const cms of cmsList) {
            for (const fp of cms.fileProbes || []) {
                probes.push({
                    path: fp.path,
                    name: cms.name,
                    category: this.CMS_CATEGORY_MAP[cms.name] ?? 'CMS',
                    confidence: 88,
                    extractor: body => fp.extractor(body),
                });
            }
        }

        const supplemental = candidates && candidates.length
            ? SUPPLEMENTAL_CMS_FILE_PROBES.filter(probe => candidates.includes(probe.name))
            : SUPPLEMENTAL_CMS_FILE_PROBES;
        for (const probe of supplemental) {
            probes.push({
                path: probe.path,
                name: probe.name,
                category: probe.category as SiteCategory,
                confidence: probe.confidence,
                allowErrorStatus: probe.allowErrorStatus,
                extractor: probe.extractor,
            });
        }

        const results = await Promise.allSettled(
            probes.map(async (probe) => {
                const res = await this.fetchPage(baseUrl + probe.path, 0, Math.min(timeoutMs, 8_000));
                if (!res || res.status >= 500 || (res.status >= 400 && !probe.allowErrorStatus)) return null;
                const version = probe.extractor(res.html, res.status, res.headers);
                if (!version) return null;
                raw[`file_${probe.name}_${probe.path}`] = `HTTP ${res.status}: ${res.html.slice(0, 140)}`;
                return {
                    name: probe.name,
                    version: version === 'detected' ? null : version,
                    category: probe.category,
                    confidence: version !== 'detected' ? 95 : probe.confidence,
                    method: `File probe: ${probe.path}`,
                    source: probe.path,
                };
            }),
        );
        return results.filter(r => r.status === 'fulfilled' && r.value).map(r => (r as any).value);
    }

    // ── SERVER TECH ───────────────────────────────────────────────────────────
    private detectServerTech(headers: Record<string, string>, raw: Record<string, string>): string[] {
        const techs: string[] = [];
        const server = headers['server'] || '';
        const powered = headers['x-powered-by'] || '';
        const via = headers['via'] || '';
        if (server) raw['server_header'] = server;
        if (powered) raw['x_powered_by'] = powered;

        if (/nginx/i.test(server)) techs.push('Nginx');
        if (/apache/i.test(server)) techs.push('Apache');
        if (/cloudflare/i.test(server)) techs.push('Cloudflare');
        if (/iis/i.test(server)) techs.push('IIS');
        if (/litespeed/i.test(server)) techs.push('LiteSpeed');
        if (/caddy/i.test(server)) techs.push('Caddy');
        if (/openresty/i.test(server)) techs.push('OpenResty');
        if (headers['x-vercel-id']) techs.push('Vercel');
        if (headers['x-nf-request-id']) techs.push('Netlify');
        if (headers['cf-ray']) techs.push('Cloudflare CDN');
        if (headers['x-amz-cf-id']) techs.push('AWS CloudFront');
        if (headers['x-azure-ref']) techs.push('Azure CDN');

        const phpMatch = powered.match(/PHP\/([\d.]+)/i);
        if (phpMatch) techs.push(`PHP/${phpMatch[1]}`);
        if (/node/i.test(powered)) techs.push('Node.js');
        if (/python/i.test(powered)) techs.push('Python');
        if (/ruby/i.test(powered)) techs.push('Ruby');
        if (/ASP\.NET/i.test(powered)) techs.push('ASP.NET');
        if (/cloudfront/i.test(via)) techs.push('CloudFront');

        return [...new Set(techs)];
    }

    // ── JS FRAMEWORKS ─────────────────────────────────────────────────────────
    private detectJsFrameworks(html: string): string[] {
        return this.JS_FRAMEWORK_PATTERNS
            .filter(fw => fw.patterns.some(p => p.test(html)))
            .map(fw => fw.name);
    }

    // ── RESOLVE ───────────────────────────────────────────────────────────────
    private resolveResult(
        url: string, signals: TechSignal[], rawSignals: Record<string, string>,
        serverTech: string[], jsFrameworks: string[], httpStatus: number | null,
        pageTitle: string | null = null,
        html: string = '',
        headers: Record<string, string> = {},
    ): CmsDetectionResult {
        if (!signals.length) {
            const noSigCat = this.determineDetailedCategory(null, 'Unknown', html, headers, serverTech);
            return { url, cms: null, version: null, versionSource: null, category: noSigCat, confidence: 0, detectionMethod: [], evidence: [], detectedAt: new Date(), rawSignals, serverTech, jsFrameworks, httpStatus, pageTitle };
        }

        const scores: Record<string, { max: number; versions: string[]; methods: string[]; category: SiteCategory; evidenceTypes: Set<EvidenceType>; signals: TechSignal[] }> = {};

        for (const s of signals) {
            if (!scores[s.name]) scores[s.name] = { max: 0, versions: [], methods: [], category: s.category, evidenceTypes: new Set(), signals: [] };
            // Keep the highest single-signal confidence (no summing)
            if (s.confidence > scores[s.name].max) scores[s.name].max = s.confidence;
            if (s.version) scores[s.name].versions.push(s.version);
            scores[s.name].methods.push(s.method);
            scores[s.name].signals.push(s);
            // Track distinct evidence category for bonus calculation
            scores[s.name].evidenceTypes.add(this.signalEvidenceType(s.method));
        }

        // Sort by (max confidence + evidence-type bonus) descending
        const sorted = Object.entries(scores).sort((a, b) => {
            const scoreA = a[1].max + Math.min((a[1].evidenceTypes.size - 1) * 6, 18);
            const scoreB = b[1].max + Math.min((b[1].evidenceTypes.size - 1) * 6, 18);
            return scoreB - scoreA;
        });
        const [topName, data] = sorted[0];

        // Require at least 40 base confidence to report a CMS
        if (data.max < 40 || this.isWeakPatternOnlyDetection(topName, data)) {
            const lowSigCat = this.determineDetailedCategory(null, 'Custom / Proprietary System', html, headers, serverTech);
            return { url, cms: null, version: null, versionSource: null, category: lowSigCat, confidence: 0, detectionMethod: ['No known tech detected'], evidence: [], detectedAt: new Date(), rawSignals, serverTech, jsFrameworks, httpStatus, pageTitle };
        }

        // Versiyani tanlash: file probe/inline > meta generator > asset URL
        const versionInfo = this.resolveVersionInfo(data.signals);
        const evidence = this.buildEvidence(topName, data.signals);
        rawSignals['_evidence'] = JSON.stringify(evidence);
        if (versionInfo.source) rawSignals['_version_source'] = versionInfo.source;

        // Final confidence: best signal + bonus per additional independent evidence type, cap 97
        const typeBonus = Math.min((data.evidenceTypes.size - 1) * 6, 18);
        const finalConfidence = Math.min(data.max + typeBonus, 97);

        return {
            url, cms: topName,
            version: versionInfo.version,
            versionSource: versionInfo.source,
            category: this.determineDetailedCategory(topName, data.category, html, headers, serverTech),
            confidence: finalConfidence,
            detectionMethod: [...new Set(data.methods)],
            evidence,
            detectedAt: new Date(), rawSignals, serverTech, jsFrameworks, httpStatus, pageTitle,
        };
    }

    private signalEvidenceType(method: string): EvidenceType {
        if (method.startsWith('File probe') || method.startsWith('RSS')) return 'file';
        if (method === 'meta generator' || method.startsWith('Wappalyzer meta')) return 'meta';
        if (method === 'Cookie' || method.startsWith('Wappalyzer cookie')) return 'cookie';
        if (method === 'Inline version') return 'inline';
        if (method.includes('Header') || method.startsWith('Wappalyzer header')) return 'header';
        if (method.startsWith('Asset') || method.includes('asset') || method.startsWith('Wappalyzer scriptSrc')) return 'asset';
        if (method.startsWith('JS bundle') || method.startsWith('Wappalyzer scripts')) return 'bundle';
        if (method.includes('robots') || method.includes('sitemap')) return 'crawl';
        if (method.includes('HTML comment')) return 'comment';
        if (method.startsWith('Pattern') || method.startsWith('Wappalyzer html') || method.startsWith('Wappalyzer text') || method.startsWith('Wappalyzer url') || method.startsWith('Wappalyzer dom')) return 'pattern';
        return 'other';
    }

    private isWeakPatternOnlyDetection(
        name: string,
        data: { max: number; category: SiteCategory; evidenceTypes: Set<EvidenceType> },
    ): boolean {
        if (data.category !== 'CMS') return false;
        if (STRONG_PATTERN_ONLY_TECHS.has(name)) return false;
        return data.evidenceTypes.size === 1 && data.evidenceTypes.has('pattern') && data.max < 58;
    }

    private buildEvidence(name: string, signals: TechSignal[]): DetectionEvidence[] {
        return signals
            .sort((a, b) => b.confidence - a.confidence)
            .map(signal => ({
                name,
                method: signal.method,
                type: this.signalEvidenceType(signal.method),
                confidence: signal.confidence,
                version: signal.version,
                source: signal.source ?? null,
            }));
    }

    private resolveVersionInfo(signals: TechSignal[]): { version: string | null; source: string | null } {
        const versioned = signals.filter(signal => signal.version);
        if (!versioned.length) return { version: null, source: null };

        const priority = [
            'File probe',
            'Inline version',
            'meta generator',
            'Asset ?ver=',
            'JS bundle',
            'RSS feed',
            'Pattern',
            'Header',
        ];
        for (const marker of priority) {
            const signal = versioned.find(sig => sig.method.includes(marker));
            if (signal?.version) return { version: signal.version, source: signal.method };
        }

        const fallback = versioned.sort((a, b) =>
            (b.version ?? '').split('.').length - (a.version ?? '').split('.').length,
        )[0];
        return { version: fallback.version, source: fallback.method };
    }

    // ── SITE NAME EXTRACTION ──────────────────────────────────────────────────
    private extractSiteName(title: string): string | null {
        if (!title) return null;

        // Split by common separators: |  -  –  —  ·  •  ::  /
        const parts = title.split(/\s*(?:\||–|—|·|•|::|\s\/\s)\s*/).map(p => p.trim()).filter(Boolean);

        if (parts.length >= 2) {
            // Heuristic: site name is usually the LAST segment (e.g. "Home | Gov.uz")
            // But if the last part looks like a page name (very short or generic), pick first
            const last  = parts[parts.length - 1];
            const first = parts[0];

            const genericWords = /^(home|bosh sahifa|главная|index|asosiy|news|yangiliklar|biz haqimizda)$/i;
            if (genericWords.test(last) && first.length > 3) return first;
            if (genericWords.test(first) && last.length > 3)  return last;

            // Prefer the shortest non-trivial segment as the brand name (max 60 chars)
            const sorted = [...parts].sort((a, b) => a.length - b.length);
            const shortest = sorted.find(p => p.length >= 3 && p.length <= 60);
            return shortest ?? last;
        }

        // Single-part title: trim if too long
        return title.length <= 80 ? title : title.slice(0, 77) + '…';
    }

    // ── DETAILED CATEGORY RESOLVER ────────────────────────────────────────────
    private determineDetailedCategory(
        cmsName: string | null,
        fallbackCategory: string,
        html: string,
        headers: Record<string, string>,
        _serverTech: string[],
    ): SiteCategory {
        // 1. Exact map lookup
        if (cmsName && this.CMS_CATEGORY_MAP[cmsName]) {
            return this.CMS_CATEGORY_MAP[cmsName]!;
        }

        // 2. PWA detection (manifest + service worker)
        const hasPwaManifest = /<link[^>]+rel=["']manifest["']/i.test(html);
        const hasServiceWorker = /serviceWorker\.register/i.test(html) || /navigator\.serviceWorker/i.test(html);
        if (hasPwaManifest && hasServiceWorker) return 'Progressive Web App (PWA)';

        // 3. Jamstack: SSG + CDN
        const isCdnDeployed = !!(headers['x-vercel-id'] || headers['x-nf-request-id'] || headers['cf-ray'] || headers['x-amz-cf-id']);
        if (fallbackCategory === 'Static Site Generator (SSG)' && isCdnDeployed) return 'Jamstack';
        if (fallbackCategory === 'Static Site Generator (SSG)') return 'Static Site Generator (SSG)';

        // 4. Frontend SPA: React/Vue/Angular but no SSR framework
        const jsFwInHtml = /react-dom|__reactFiber|\[data-v-|ng-version/i.test(html);
        const noServerFramework = !cmsName || fallbackCategory === 'Backend Framework';
        if (jsFwInHtml && noServerFramework && !/<html[^>]*lang/i.test(html)) {
            return 'Frontend Framework / SPA';
        }

        // 5. API-only: JSON content type
        if (headers['content-type']?.includes('application/json')) return 'API-only Backend';

        // 6. SSR: Vercel/Netlify + framework
        if (headers['x-vercel-id'] || headers['x-nf-request-id']) {
            if (fallbackCategory === 'Backend Framework' || fallbackCategory === 'Fullstack Framework') return 'Server-Side Rendered (SSR)';
        }

        // 7. Pass through new detailed categories as-is
        const passthrough: SiteCategory[] = [
            'CMS', 'E-commerce CMS', 'Backend Framework', 'Frontend Framework / SPA',
            'Fullstack Framework', 'Headless CMS', 'Static Website', 'Static Site Generator (SSG)',
            'Jamstack', 'Server-Side Rendered (SSR)', 'Progressive Web App (PWA)',
            'Forum Engine', 'Wiki Engine', 'Blog Engine',
            'Learning Management System (LMS)', 'CRM / ERP Web System',
            'Web Builder / No-Code Platform', 'Custom / Proprietary System',
            'API-only Backend', 'Unknown',
        ];
        if ((passthrough as string[]).includes(fallbackCategory)) return fallbackCategory as SiteCategory;

        return 'Unknown';
    }

    // ── FETCH PAGE ────────────────────────────────────────────────────────────
    // attempt 0: proxy/keep-alive agent + brotli
    // attempt 1: bare axios (no shared agent), gzip/deflate only — works around
    //            keep-alive socket reuse and brotli decompression failures
    //            observed on some IIS / static-host targets (lex.uz, asaka.uz...)
    private async fetchPage(
        url: string,
        attempt = 0,
        timeoutMs = 20_000,
    ): Promise<{ html: string; headers: Record<string, string>; status: number } | null> {
        // Skip if domain is in 429/403 cooldown
        if (this.getDomainCooldown(url) > 0) return null;

        const bare = attempt > 0;
        const { agent: proxyAgent, proxyUrl } = bare
            ? { agent: undefined, proxyUrl: null as string | null }
            : this.getNextAgent();
        const usingProxy = !!proxyUrl && !!proxyAgent && !bare;
        const requestTimeoutMs = usingProxy ? Math.min(timeoutMs, this.proxyFetchTimeoutMs) : timeoutMs;
        try {
            const res: AxiosResponse = await axios.get(url, {
                timeout: requestTimeoutMs,
                signal: AbortSignal.timeout(requestTimeoutMs),
                maxRedirects: 5,
                maxContentLength: 5 * 1024 * 1024,
                maxBodyLength: 5 * 1024 * 1024,
                decompress: true,
                responseType: 'text',
                transitional: { silentJSONParsing: true, forcedJSONParsing: false },
                ...(bare
                    ? {}
                    : { httpAgent: proxyAgent ?? this.httpAgent, httpsAgent: proxyAgent ?? this.httpsAgent }),
                headers: {
                    'User-Agent': this.randomUserAgent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'uz-UZ,uz;q=0.9,en-US;q=0.8,en;q=0.7,ru;q=0.6',
                    'Accept-Encoding': bare ? 'gzip, deflate' : 'gzip, deflate, br',
                    'Connection': bare ? 'close' : 'keep-alive',
                },
                validateStatus: () => true,
            });

            if (usingProxy && this.isProxySuspectResponse(res.status, res.data) && attempt < 1) {
                this.reportProxyResult(proxyUrl, false);
                return this.fetchPage(url, attempt + 1, timeoutMs);
            }

            // Per-domain cooldown for 429/403
            if (res.status === 429 || res.status === 403) {
                this.setDomainCooldown(url);
            }

            this.reportProxyResult(proxyUrl, true);

            return {
                html: typeof res.data === 'string' ? res.data : JSON.stringify(res.data),
                headers: this.normalizeHeaders(res.headers as Record<string, string>),
                status: res.status,
            };
        } catch (err: any) {
            this.reportProxyResult(proxyUrl, false);

            const code = err?.code;
            const transient =
                code === 'ECONNRESET' || code === 'ETIMEDOUT' ||
                code === 'ECONNABORTED' || code === 'EAI_AGAIN' ||
                code === 'ERR_BAD_RESPONSE' || code === 'EPROTO' ||
                code === 'ERR_BROTLI_DECOMPRESSION_FAILED' ||
                code === 'Z_BUF_ERROR' || code === 'Z_DATA_ERROR' ||
                code === 'ERR_CANCELED' || code === 'ABORT_ERR';
            if ((proxyUrl || transient) && attempt < 1) {
                if (!proxyUrl) await new Promise(r => setTimeout(r, 300));
                return this.fetchPage(url, attempt + 1, timeoutMs);
            }
            return null;
        }
    }

    private readonly USER_AGENTS = [
        // Chrome — Windows/Mac/Linux, multiple versions
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        // Firefox
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
        // Safari
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
        // Edge
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
        // Mobile (Android Chrome + iOS Safari)
        'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    ];

    private randomUserAgent(): string {
        return this.USER_AGENTS[Math.floor(Math.random() * this.USER_AGENTS.length)];
    }

    private normalizeHeaders(headers: Record<string, any>): Record<string, string> {
        const normalized: Record<string, string> = {};
        for (const [key, value] of Object.entries(headers || {})) {
            normalized[key.toLowerCase()] = Array.isArray(value) ? value.join('; ') : String(value);
        }
        return normalized;
    }

    private normalizeTimeout(timeoutMs: number | undefined, mode: 'FAST' | 'FULL'): number {
        const fallback = mode === 'FAST' ? 5_000 : 20_000;
        const raw = Number(timeoutMs || fallback);
        const min = mode === 'FAST' ? 2_000 : 5_000;
        const max = mode === 'FAST' ? 15_000 : 30_000;
        return Math.min(max, Math.max(min, Number.isFinite(raw) ? Math.round(raw) : fallback));
    }

    private normalizeUrl(url: string): string {
        if (!url.startsWith('http')) url = 'https://' + url;
        return url.replace(/\/$/, '');
    }
}
