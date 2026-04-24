import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';

export type SiteCategory = 'CMS' | 'Framework' | 'Headless' | 'Static' | 'Custom' | 'Unknown';

export interface CmsDetectionResult {
    url: string;
    cms: string | null;
    version: string | null;
    category: SiteCategory;
    confidence: number;
    detectionMethod: string[];
    detectedAt: Date;
    rawSignals: Record<string, string>;
    serverTech: string[];
    jsFrameworks: string[];
}

interface TechSignal {
    name: string;
    version: string | null;
    category: SiteCategory;
    confidence: number;
    method: string;
}

@Injectable()
export class CmsDetectorService {
    private readonly logger = new Logger(CmsDetectorService.name);

    private readonly CMS_PATTERNS: Array<{
        name: string; patterns: RegExp[];
        fileProbes?: Array<{ path: string; extractor: (b: string) => string | null }>;
        headerKeys?: Array<{ key: string; pattern: RegExp }>;
    }> = [
            {
                name: 'WordPress', patterns: [/\/wp-content\//i, /\/wp-includes\//i, /wp-json/i],
                fileProbes: [
                    { path: '/readme.html', extractor: b => b.match(/Version\s+([\d.]+)/i)?.[1] || null },
                    { path: '/wp-links-opml.php', extractor: b => b.match(/generator="WordPress\/([\d.]+)"/i)?.[1] || null },
                ],
            },
            {
                name: 'Joomla', patterns: [/\/components\/com_/i, /\/media\/jui\//i],
                fileProbes: [
                    { path: '/administrator/manifests/files/joomla.xml', extractor: b => b.match(/<version>([\d.]+)<\/version>/i)?.[1] || null },
                ],
            },
            {
                name: 'Drupal', patterns: [/Drupal\.settings/i, /\/sites\/default\/files\//i],
                fileProbes: [
                    { path: '/CHANGELOG.txt', extractor: b => b.match(/Drupal\s+([\d.]+)/i)?.[1] || null },
                    { path: '/core/CHANGELOG.txt', extractor: b => b.match(/Drupal\s+([\d.]+)/i)?.[1] || null },
                ],
            },
            {
                name: 'Bitrix', patterns: [/\/bitrix\/js\//i, /\/bitrix\/templates\//i, /BX\.ready/i],
                fileProbes: [
                    { path: '/bitrix/modules/main/install/version.php', extractor: b => b.match(/VERSION\s*=\s*["']([\d.]+)["']/i)?.[1] || null },
                ],
            },
            { name: 'MODX', patterns: [/powered by MODX/i, /modx\.com/i, /\/assets\/components\//i] },
            { name: 'OctoberCMS', patterns: [/october\.cms/i, /\/plugins\/rainlab\//i] },
            { name: 'Shopify', patterns: [/cdn\.shopify\.com/i, /Shopify\.theme/i, /myshopify\.com/i], headerKeys: [{ key: 'x-shopid', pattern: /.+/ }] },
            { name: 'Ghost', patterns: [/ghost\.org/i, /\/ghost\/api\//i] },
            { name: 'TYPO3', patterns: [/typo3/i, /\/typo3conf\//i] },
            { name: 'Wix', patterns: [/static\.wixstatic\.com/i, /wix\.com/i] },
            { name: 'Squarespace', patterns: [/squarespace\.com/i, /static\.squarespace\.com/i] },
            { name: 'Webflow', patterns: [/webflow\.com/i], headerKeys: [{ key: 'x-wf-site', pattern: /.+/ }] },
            { name: 'Tilda', patterns: [/tilda\.cc/i, /tildacdn\.com/i] },
        ];

    private readonly FRAMEWORK_PATTERNS: Array<{
        name: string; patterns: RegExp[];
        headerKeys?: Array<{ key: string; pattern: RegExp }>;
        version?: RegExp;
    }> = [
            { name: 'Next.js', patterns: [/\/_next\/static\//i, /__NEXT_DATA__/i], headerKeys: [{ key: 'x-powered-by', pattern: /Next\.js/i }], version: /Next\.js\s*([\d.]+)/i },
            { name: 'Nuxt.js', patterns: [/\/_nuxt\//i, /__nuxt/i], headerKeys: [{ key: 'x-powered-by', pattern: /nuxt/i }] },
            { name: 'SvelteKit', patterns: [/\/_app\/immutable\//i, /__sveltekit/i] },
            { name: 'Remix', patterns: [/__remixContext/i, /__remixRouteModules/i] },
            { name: 'Astro', patterns: [/astro-island/i, /@astrojs/i] },
            { name: 'Laravel', patterns: [/laravel_session/i, /laravel/i], headerKeys: [{ key: 'x-powered-by', pattern: /PHP/i }] },
            { name: 'Django', patterns: [/csrfmiddlewaretoken/i, /django/i] },
            { name: 'Ruby on Rails', patterns: [/authenticity_token/i], headerKeys: [{ key: 'x-runtime', pattern: /[\d.]+/ }] },
            { name: 'Express.js', patterns: [], headerKeys: [{ key: 'x-powered-by', pattern: /Express/i }] },
            { name: 'ASP.NET', patterns: [/__VIEWSTATE/i, /\.aspx/i], headerKeys: [{ key: 'x-powered-by', pattern: /ASP\.NET/i }], version: /ASP\.NET\s*([\d.]+)/i },
            { name: 'Spring Boot', patterns: [/Whitelabel Error Page/i], headerKeys: [{ key: 'x-application-context', pattern: /.+/ }] },
            { name: 'FastAPI', patterns: [/fastapi/i] },
        ];

    private readonly HEADLESS_PATTERNS: Array<{ name: string; patterns: RegExp[] }> = [
        { name: 'Contentful', patterns: [/contentful\.com/i, /cdn\.contentful\.com/i] },
        { name: 'Sanity', patterns: [/sanity\.io/i, /cdn\.sanity\.io/i] },
        { name: 'Strapi', patterns: [/strapi/i] },
        { name: 'Directus', patterns: [/directus/i, /directus\.io/i] },
        { name: 'Prismic', patterns: [/prismic\.io/i, /cdn\.prismic\.io/i] },
        { name: 'DatoCMS', patterns: [/datocms\.com/i, /datocms-assets\.com/i] },
        { name: 'Hygraph', patterns: [/hygraph\.com/i, /graphcms\.com/i] },
        { name: 'Storyblok', patterns: [/storyblok\.com/i, /a\.storyblok\.com/i] },
        { name: 'KeystoneJS', patterns: [/keystonejs/i] },
        { name: 'PayloadCMS', patterns: [/payloadcms/i, /payload-cms/i] },
    ];

    private readonly STATIC_PATTERNS: Array<{
        name: string; patterns: RegExp[];
        headerKeys?: Array<{ key: string; pattern: RegExp }>;
        version?: RegExp;
    }> = [
            { name: 'Gatsby', patterns: [/___gatsby/i, /gatsby-image/i, /\/page-data\//i], version: /gatsby\/([\d.]+)/i },
            { name: 'Hugo', patterns: [/content="Hugo/i], headerKeys: [{ key: 'x-generator', pattern: /Hugo/i }], version: /Hugo\s*([\d.]+)/i },
            { name: 'Jekyll', patterns: [/jekyll/i, /jekyll-theme/i], version: /jekyll\s*([\d.]+)/i },
            { name: 'Eleventy', patterns: [/eleventy/i, /11ty\.dev/i] },
            { name: 'VitePress', patterns: [/vitepress/i, /\.vitepress\//i] },
            { name: 'Docusaurus', patterns: [/docusaurus/i] },
            { name: 'Hexo', patterns: [/content="Hexo/i], version: /Hexo\s*([\d.]+)/i },
            { name: 'MkDocs', patterns: [/mkdocs/i] },
            { name: 'Astro Static', patterns: [/astro\.build/i] },
        ];

    private readonly JS_FRAMEWORK_PATTERNS: Array<{ name: string; patterns: RegExp[] }> = [
        { name: 'React', patterns: [/react-dom/i, /__reactFiber/i, /ReactDOM/i] },
        { name: 'Vue', patterns: [/vue\.js/i, /\[data-v-/i, /Vue\.component/i] },
        { name: 'Angular', patterns: [/ng-version/i, /angular\.min\.js/i] },
        { name: 'Svelte', patterns: [/svelte/i] },
        { name: 'Alpine', patterns: [/alpinejs/i, /x-data=/i] },
        { name: 'HTMX', patterns: [/htmx\.org/i, /hx-get=/i] },
        { name: 'Ember', patterns: [/ember\.js/i, /ember-cli/i] },
    ];

    // ── MAIN ─────────────────────────────────────────
    async detect(url: string): Promise<CmsDetectionResult> {
        const baseUrl = this.normalizeUrl(url);
        const signals: TechSignal[] = [];
        const rawSignals: Record<string, string> = {};
        let serverTech: string[] = [];
        let jsFrameworks: string[] = [];

        try {
            const mainPage = await this.fetchPage(baseUrl);
            if (mainPage) {
                serverTech = this.detectServerTech(mainPage.headers, rawSignals);
                jsFrameworks = this.detectJsFrameworks(mainPage.html);
                signals.push(...this.checkPatternGroup(mainPage.html, mainPage.headers, this.CMS_PATTERNS, 'CMS', rawSignals));
                signals.push(...this.checkPatternGroup(mainPage.html, mainPage.headers, this.FRAMEWORK_PATTERNS, 'Framework', rawSignals));
                signals.push(...this.checkPatternGroup(mainPage.html, mainPage.headers, this.HEADLESS_PATTERNS, 'Headless', rawSignals));
                signals.push(...this.checkPatternGroup(mainPage.html, mainPage.headers, this.STATIC_PATTERNS, 'Static', rawSignals));
                signals.push(...this.checkMetaGenerator(mainPage.html, rawSignals));
            }
            signals.push(...await this.checkCmsFileProbes(baseUrl, rawSignals));
        } catch (err) {
            this.logger.warn(`Detection failed for ${url}: ${String(err)}`);
        }

        return this.resolveResult(baseUrl, signals, rawSignals, serverTech, jsFrameworks);
    }

    private checkPatternGroup(
        html: string, headers: Record<string, string>,
        group: Array<{ name: string; patterns: RegExp[]; headerKeys?: any[]; version?: RegExp }>,
        category: SiteCategory, raw: Record<string, string>,
    ): TechSignal[] {
        const signals: TechSignal[] = [];
        for (const tech of group) {
            let matched = false;
            let version: string | null = null;

            for (const pattern of tech.patterns || []) {
                if (pattern.test(html)) {
                    matched = true;
                    raw[`html_${tech.name}`] = pattern.toString();
                    if (tech.version) { const m = html.match(tech.version); if (m?.[1]) version = m[1]; }
                }
            }
            for (const hk of tech.headerKeys || []) {
                const val = headers[hk.key.toLowerCase()] || '';
                if (hk.pattern.test(val)) {
                    matched = true;
                    raw[`header_${tech.name}`] = val;
                    if (tech.version) { const m = val.match(tech.version); if (m?.[1]) version = m[1]; }
                }
            }
            if (matched) signals.push({ name: tech.name, version, category, confidence: category === 'CMS' ? 85 : 80, method: 'HTML/Header pattern' });
        }
        return signals;
    }

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
            { pattern: /Hugo\s*([\d.]*)/i, name: 'Hugo', category: 'Static' },
            { pattern: /Jekyll\s*([\d.]*)/i, name: 'Jekyll', category: 'Static' },
            { pattern: /Hexo\s*([\d.]*)/i, name: 'Hexo', category: 'Static' },
            { pattern: /Gatsby\s*([\d.]*)/i, name: 'Gatsby', category: 'Static' },
            { pattern: /Eleventy\s*([\d.]*)/i, name: 'Eleventy', category: 'Static' },
            { pattern: /Next\.js\s*([\d.]*)/i, name: 'Next.js', category: 'Framework' },
            { pattern: /Nuxt\s*([\d.]*)/i, name: 'Nuxt.js', category: 'Framework' },
            { pattern: /Astro\s*([\d.]*)/i, name: 'Astro', category: 'Static' },
        ];

        for (const { pattern, name, category } of matchers) {
            const match = generator.match(pattern);
            if (match) signals.push({ name, version: match[1]?.trim() || null, category, confidence: 95, method: 'meta generator tag' });
        }
        return signals;
    }

    private async checkCmsFileProbes(baseUrl: string, raw: Record<string, string>): Promise<TechSignal[]> {
        const probes: Array<{ path: string; name: string; extractor: (b: string) => string | null }> = [];
        for (const cms of this.CMS_PATTERNS) {
            for (const fp of cms.fileProbes || []) probes.push({ path: fp.path, name: cms.name, extractor: fp.extractor });
        }
        const results = await Promise.allSettled(probes.map(async (probe) => {
            const res = await this.fetchPage(baseUrl + probe.path);
            if (!res || res.status >= 400) return null;
            const version = probe.extractor(res.html);
            raw[`file_${probe.name}`] = res.html.slice(0, 200);
            return { name: probe.name, version, category: 'CMS' as SiteCategory, confidence: 92, method: `File: ${probe.path}` };
        }));
        return results.filter(r => r.status === 'fulfilled' && r.value).map(r => (r as any).value);
    }

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
        if (headers['x-vercel-id']) techs.push('Vercel');
        if (headers['x-nf-request-id']) techs.push('Netlify');
        if (headers['cf-ray']) techs.push('Cloudflare CDN');
        if (headers['x-amz-cf-id']) techs.push('AWS CloudFront');

        const phpMatch = powered.match(/PHP\/([\d.]+)/i);
        if (phpMatch) techs.push(`PHP/${phpMatch[1]}`);
        if (/node/i.test(powered)) techs.push('Node.js');
        if (/python/i.test(powered)) techs.push('Python');
        if (/ruby/i.test(powered)) techs.push('Ruby');
        if (/ASP\.NET/i.test(powered)) techs.push('ASP.NET');
        if (/cloudfront/i.test(via)) techs.push('CloudFront');

        return [...new Set(techs)];
    }

    private detectJsFrameworks(html: string): string[] {
        return this.JS_FRAMEWORK_PATTERNS.filter(fw => fw.patterns.some(p => p.test(html))).map(fw => fw.name);
    }

    private resolveResult(
        url: string, signals: TechSignal[], rawSignals: Record<string, string>,
        serverTech: string[], jsFrameworks: string[],
    ): CmsDetectionResult {
        if (!signals.length) {
            return { url, cms: null, version: null, category: 'Unknown', confidence: 0, detectionMethod: [], detectedAt: new Date(), rawSignals, serverTech, jsFrameworks };
        }

        const scores: Record<string, { total: number; versions: string[]; methods: string[]; category: SiteCategory }> = {};
        for (const s of signals) {
            if (!scores[s.name]) scores[s.name] = { total: 0, versions: [], methods: [], category: s.category };
            scores[s.name].total += s.confidence;
            if (s.version) scores[s.name].versions.push(s.version);
            scores[s.name].methods.push(s.method);
        }

        const [topName, data] = Object.entries(scores).sort((a, b) => b[1].total - a[1].total)[0];

        if (data.total < 50) {
            return { url, cms: null, version: null, category: 'Custom', confidence: 0, detectionMethod: ['No known tech detected'], detectedAt: new Date(), rawSignals, serverTech, jsFrameworks };
        }

        return {
            url, cms: topName, version: this.resolveVersion(data.versions),
            category: data.category, confidence: Math.min(data.total, 100),
            detectionMethod: [...new Set(data.methods)],
            detectedAt: new Date(), rawSignals, serverTech, jsFrameworks,
        };
    }

    private resolveVersion(versions: string[]): string | null {
        if (!versions.length) return null;
        return versions.sort((a, b) => b.split('.').length - a.split('.').length)[0];
    }

    private async fetchPage(url: string): Promise<{ html: string; headers: Record<string, string>; status: number } | null> {
        try {
            const res: AxiosResponse = await axios.get(url, {
                timeout: 10000, maxRedirects: 5,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                },
                validateStatus: () => true,
            });
            return { html: typeof res.data === 'string' ? res.data : JSON.stringify(res.data), headers: res.headers as Record<string, string>, status: res.status };
        } catch { return null; }
    }

    private normalizeUrl(url: string): string {
        if (!url.startsWith('http')) url = 'https://' + url;
        return url.replace(/\/$/, '');
    }
}