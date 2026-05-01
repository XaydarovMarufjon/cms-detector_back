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
    httpStatus: number | null;
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

    // ── CMS PATTERNS (kengaytirilgan .uz uchun) ──────────────────────────────
    private readonly CMS_PATTERNS: Array<{
        name: string; patterns: RegExp[];
        fileProbes?: Array<{ path: string; extractor: (b: string) => string | null }>;
        headerKeys?: Array<{ key: string; pattern: RegExp }>;
    }> = [
            // ── WordPress (o'zbekcha temalar ham) ──
            {
                name: 'WordPress',
                patterns: [
                    /\/wp-content\//i,
                    /\/wp-includes\//i,
                    /wp-json/i,
                    /wp-emoji/i,
                    /wp-block/i,
                    /\/wp-content\/uploads\//i,
                    /\/wp-content\/themes\//i,
                    /\/wp-content\/plugins\//i,
                    // O'zbek WordPress temalari
                    /class="wp-/i,
                    /wpb_wrapper/i,
                    /wpcf7/i,          // Contact Form 7
                    /elementor/i,      // Elementor page builder
                    /revslider/i,      // Revolution Slider
                    /wpml/i,           // WPML translation
                ],
                fileProbes: [
                    { path: '/readme.html', extractor: b => b.match(/Version\s+([\d.]+)/i)?.[1] || null },
                    { path: '/wp-login.php', extractor: b => b.includes('WordPress') ? 'detected' : null },
                    { path: '/wp-links-opml.php', extractor: b => b.match(/generator="WordPress\/([\d.]+)"/i)?.[1] || null },
                    { path: '/wp-admin/', extractor: b => b.includes('WordPress') ? 'detected' : null },
                    { path: '/wp-json/wp/v2/', extractor: b => { try { const j = JSON.parse(b); return j?.namespace ? 'detected' : null; } catch { return null; } } },
                ],
            },
            // ── Bitrix (1C-Bitrix — O'zbekistonda keng tarqalgan) ──
            {
                name: 'Bitrix',
                patterns: [
                    /\/bitrix\/js\//i,
                    /\/bitrix\/templates\//i,
                    /\/bitrix\/components\//i,
                    /\/bitrix\/cache\//i,
                    /BX\.ready/i,
                    /BX\.message/i,
                    /bitrix_sessid/i,
                    /1c-bitrix/i,
                    /bitrixcloud/i,
                    /\/upload\/resize_cache\//i,   // Bitrix resize cache
                    /BXMainFilter/i,
                    /bitrix\/admin/i,
                    /\/bitrix\/tools\//i,
                ],
                fileProbes: [
                    { path: '/bitrix/admin/', extractor: b => b.includes('Bitrix') ? 'detected' : null },
                    { path: '/bitrix/modules/main/install/version.php', extractor: b => b.match(/VERSION\s*=\s*["']([\d.]+)["']/i)?.[1] || null },
                    { path: '/bitrix/.settings.php', extractor: b => b.includes('bitrix') ? 'detected' : null },
                ],
                headerKeys: [
                    { key: 'x-powered-cms', pattern: /bitrix/i },
                    { key: 'set-cookie', pattern: /BITRIX_SM/i },
                ],
            },
            // ── Joomla ──
            {
                name: 'Joomla',
                patterns: [
                    /\/components\/com_/i,
                    /\/media\/jui\//i,
                    /\/media\/system\/js\//i,
                    /Joomla!/i,
                    /\/templates\/[^/]+\/css\//i,
                    /option=com_/i,
                    /joomla/i,
                ],
                fileProbes: [
                    { path: '/administrator/', extractor: b => b.includes('Joomla') ? 'detected' : null },
                    { path: '/administrator/manifests/files/joomla.xml', extractor: b => b.match(/<version>([\d.]+)<\/version>/i)?.[1] || null },
                    { path: '/language/en-GB/en-GB.xml', extractor: b => b.match(/<version>([\d.]+)<\/version>/i)?.[1] || null },
                ],
            },
            // ── Drupal ──
            {
                name: 'Drupal',
                patterns: [
                    /Drupal\.settings/i,
                    /\/sites\/default\/files\//i,
                    /\/sites\/all\/modules\//i,
                    /drupal\.js/i,
                    /drupal/i,
                    /\/core\/misc\/drupal\.js/i,
                ],
                fileProbes: [
                    { path: '/CHANGELOG.txt', extractor: b => b.match(/Drupal\s+([\d.]+)/i)?.[1] || null },
                    { path: '/core/CHANGELOG.txt', extractor: b => b.match(/Drupal\s+([\d.]+)/i)?.[1] || null },
                    { path: '/core/core.services.yml', extractor: b => b.includes('drupal') ? 'detected' : null },
                ],
            },
            // ── MODX ──
            {
                name: 'MODX',
                patterns: [
                    /powered by MODX/i,
                    /modx\.com/i,
                    /\/assets\/components\//i,
                    /\/assets\/snippets\//i,
                    /MODx/i,
                    /modxcloud/i,
                ],
            },
            // ── OctoberCMS ──
            {
                name: 'OctoberCMS',
                patterns: [/october\.cms/i, /\/plugins\/rainlab\//i, /\/themes\/[^/]+\/assets\//i],
            },
            // ── Shopify ──
            {
                name: 'Shopify',
                patterns: [/cdn\.shopify\.com/i, /Shopify\.theme/i, /myshopify\.com/i, /shopify\.com\/s\/files/i],
                headerKeys: [{ key: 'x-shopid', pattern: /.+/ }],
            },
            // ── Ghost ──
            {
                name: 'Ghost',
                patterns: [/ghost\.org/i, /\/ghost\/api\//i, /content="Ghost/i],
            },
            // ── TYPO3 ──
            {
                name: 'TYPO3',
                patterns: [/typo3/i, /\/typo3conf\//i, /TYPO3\.CMS/i],
            },
            // ── Wix ──
            {
                name: 'Wix',
                patterns: [/static\.wixstatic\.com/i, /wix\.com/i, /wixsite\.com/i],
            },
            // ── Squarespace ──
            {
                name: 'Squarespace',
                patterns: [/squarespace\.com/i, /static\.squarespace\.com/i],
            },
            // ── Webflow ──
            {
                name: 'Webflow',
                patterns: [/webflow\.com/i, /assets\.website-files\.com/i],
                headerKeys: [{ key: 'x-wf-site', pattern: /.+/ }],
            },
            // ── Tilda (O'zbekistonda mashhur) ──
            {
                name: 'Tilda',
                patterns: [/tilda\.cc/i, /tildacdn\.com/i, /tilda\.ws/i],
            },
            // ── OpenCart (O'zbek e-commerce) ──
            {
                name: 'OpenCart',
                patterns: [/route=common\//i, /opencart/i, /catalog\/view\/theme/i, /index\.php\?route=/i],
                fileProbes: [
                    { path: '/index.php?route=common/home', extractor: b => b.includes('OpenCart') ? 'detected' : null },
                ],
            },
            // ── PrestaShop ──
            {
                name: 'PrestaShop',
                patterns: [/prestashop/i, /\/themes\/classic\//i, /id_product=/i],
            },
            // ── WooCommerce (WordPress plugin) ──
            {
                name: 'WooCommerce',
                patterns: [/woocommerce/i, /\/wc-api\//i, /class="woocommerce/i],
            },
            // ── Yii Framework (O'zbek saytlarda keng) ──
            {
                name: 'Yii',
                patterns: [/yii/i, /YII_DEBUG/i, /yii2/i, /\/web\/assets\//i],
            },
            // ── Laravel (O'zbek developerlar ko'p ishlatadi) ──
            {
                name: 'Laravel',
                patterns: [/laravel_session/i, /laravel/i, /csrf-token.*Laravel/i],
                headerKeys: [{ key: 'x-powered-by', pattern: /PHP/i }],
            },
            // ── Uzbek government CMS (davlat saytlari) ──
            {
                name: 'UzGovCMS',
                patterns: [/hukumat\.uz/i, /gov\.uz/i, /e-hukumat/i, /uzgov/i],
            },
        ];

    // ── FRAMEWORK PATTERNS ───────────────────────────────────────────────────
    private readonly FRAMEWORK_PATTERNS: Array<{
        name: string; patterns: RegExp[];
        headerKeys?: Array<{ key: string; pattern: RegExp }>;
        version?: RegExp;
    }> = [
            { name: 'Next.js', patterns: [/\/_next\/static\//i, /__NEXT_DATA__/i], headerKeys: [{ key: 'x-powered-by', pattern: /Next\.js/i }] },
            { name: 'Nuxt.js', patterns: [/\/_nuxt\//i, /__nuxt/i, /nuxtApp/i] },
            { name: 'SvelteKit', patterns: [/\/_app\/immutable\//i, /__sveltekit/i] },
            { name: 'Remix', patterns: [/__remixContext/i, /__remixRouteModules/i] },
            { name: 'Astro', patterns: [/astro-island/i, /@astrojs/i] },
            { name: 'Django', patterns: [/csrfmiddlewaretoken/i, /django/i] },
            { name: 'Ruby on Rails', patterns: [/authenticity_token/i], headerKeys: [{ key: 'x-runtime', pattern: /[\d.]+/ }] },
            { name: 'Express.js', patterns: [], headerKeys: [{ key: 'x-powered-by', pattern: /Express/i }] },
            { name: 'ASP.NET', patterns: [/__VIEWSTATE/i, /\.aspx/i], headerKeys: [{ key: 'x-powered-by', pattern: /ASP\.NET/i }] },
            { name: 'Spring Boot', patterns: [/Whitelabel Error Page/i] },
            { name: 'FastAPI', patterns: [/fastapi/i] },
            { name: 'CodeIgniter', patterns: [/ci_session/i, /codeigniter/i] },
            { name: 'Symfony', patterns: [/symfony/i, /sf_redirect/i] },
            { name: 'CakePHP', patterns: [/cakephp/i, /CAKEPHP/i] },
            // O'zbek developerlar ishlatadigan
            { name: 'Yii2', patterns: [/yii2/i, /_csrf.*yii/i] },
            { name: 'Flask', patterns: [/flask/i, /Werkzeug/i], headerKeys: [{ key: 'server', pattern: /Werkzeug/i }] },
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
    ];

    // ── STATIC SITE ───────────────────────────────────────────────────────────
    private readonly STATIC_PATTERNS: Array<{
        name: string; patterns: RegExp[];
        headerKeys?: Array<{ key: string; pattern: RegExp }>;
        version?: RegExp;
    }> = [
            { name: 'Gatsby', patterns: [/___gatsby/i, /\/page-data\//i] },
            { name: 'Hugo', patterns: [/content="Hugo/i], headerKeys: [{ key: 'x-generator', pattern: /Hugo/i }], version: /Hugo\s*([\d.]+)/i },
            { name: 'Jekyll', patterns: [/jekyll/i, /jekyll-theme/i] },
            { name: 'Eleventy', patterns: [/eleventy/i] },
            { name: 'VitePress', patterns: [/vitepress/i] },
            { name: 'Docusaurus', patterns: [/docusaurus/i] },
            { name: 'Hexo', patterns: [/content="Hexo/i] },
        ];

    // ── JS FRAMEWORKS ─────────────────────────────────────────────────────────
    private readonly JS_FRAMEWORK_PATTERNS: Array<{ name: string; patterns: RegExp[] }> = [
        { name: 'React', patterns: [/react-dom/i, /__reactFiber/i, /ReactDOM/i] },
        { name: 'Vue', patterns: [/vue\.js/i, /\[data-v-/i, /Vue\.component/i, /vue\.min\.js/i] },
        { name: 'Angular', patterns: [/ng-version/i, /angular\.min\.js/i, /NgModule/i] },
        { name: 'Svelte', patterns: [/svelte/i] },
        { name: 'Alpine', patterns: [/alpinejs/i, /x-data=/i] },
        { name: 'jQuery', patterns: [/jquery/i, /jQuery/i] },       // O'zbek saytlarda jQuery keng
        { name: 'HTMX', patterns: [/htmx\.org/i, /hx-get=/i] },
        { name: 'Ember', patterns: [/ember\.js/i] },
    ];

    // ── MAIN ─────────────────────────────────────────────────────────────────
    async detect(url: string): Promise<CmsDetectionResult> {
        const baseUrl = this.normalizeUrl(url);
        const signals: TechSignal[] = [];
        const rawSignals: Record<string, string> = {};
        let serverTech: string[] = [];
        let jsFrameworks: string[] = [];
        let httpStatus: number | null = null;

        try {
            // Bir vaqtda main page + robots.txt + sitemap.xml olamiz
            const [mainPage, robotsPage, sitemapPage] = await Promise.allSettled([
                this.fetchPage(baseUrl),
                this.fetchPage(baseUrl + '/robots.txt'),
                this.fetchPage(baseUrl + '/sitemap.xml'),
            ]);

            const main = mainPage.status === 'fulfilled' ? mainPage.value : null;
            const robots = robotsPage.status === 'fulfilled' ? robotsPage.value : null;
            const sitemap = sitemapPage.status === 'fulfilled' ? sitemapPage.value : null;

            if (main) {
                httpStatus = main.status;
                serverTech = this.detectServerTech(main.headers, rawSignals);
                jsFrameworks = this.detectJsFrameworks(main.html);

                signals.push(...this.checkPatternGroup(main.html, main.headers, this.CMS_PATTERNS, 'CMS', rawSignals));
                signals.push(...this.checkPatternGroup(main.html, main.headers, this.FRAMEWORK_PATTERNS, 'Framework', rawSignals));
                signals.push(...this.checkPatternGroup(main.html, main.headers, this.HEADLESS_PATTERNS, 'Headless', rawSignals));
                signals.push(...this.checkPatternGroup(main.html, main.headers, this.STATIC_PATTERNS, 'Static', rawSignals));
                signals.push(...this.checkMetaGenerator(main.html, rawSignals));
                signals.push(...this.checkJsCssVersions(main.html, rawSignals));
            }

            // robots.txt va sitemap dan qo'shimcha signal
            if (robots?.html) signals.push(...this.checkRobotsTxt(robots.html, rawSignals));
            if (sitemap?.html) signals.push(...this.checkSitemap(sitemap.html, rawSignals));

            // File probes
            signals.push(...await this.checkCmsFileProbes(baseUrl, rawSignals));

        } catch (err) {
            this.logger.warn(`Detection failed for ${url}: ${String(err)}`);
        }

        return this.resolveResult(baseUrl, signals, rawSignals, serverTech, jsFrameworks, httpStatus);
    }

    // ── ROBOTS.TXT tekshirish ─────────────────────────────────────────────────
    private checkRobotsTxt(body: string, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];
        raw['robots_txt'] = body.slice(0, 300);

        const checks: Array<{ pattern: RegExp; name: string; category: SiteCategory }> = [
            { pattern: /\/wp-admin/i, name: 'WordPress', category: 'CMS' },
            { pattern: /\/wp-content/i, name: 'WordPress', category: 'CMS' },
            { pattern: /\/bitrix\//i, name: 'Bitrix', category: 'CMS' },
            { pattern: /\/administrator\//i, name: 'Joomla', category: 'CMS' },
            { pattern: /\/user\/login/i, name: 'Drupal', category: 'CMS' },
            { pattern: /opencart/i, name: 'OpenCart', category: 'CMS' },
        ];

        for (const { pattern, name, category } of checks) {
            if (pattern.test(body)) {
                signals.push({ name, version: null, category, confidence: 70, method: 'robots.txt' });
            }
        }
        return signals;
    }

    // ── SITEMAP tekshirish ────────────────────────────────────────────────────
    private checkSitemap(body: string, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];
        raw['sitemap'] = body.slice(0, 300);

        if (/\/wp-content\//i.test(body) || /yoast/i.test(body)) {
            signals.push({ name: 'WordPress', version: null, category: 'CMS', confidence: 75, method: 'sitemap.xml' });
        }
        if (/\/bitrix\//i.test(body)) {
            signals.push({ name: 'Bitrix', version: null, category: 'CMS', confidence: 75, method: 'sitemap.xml' });
        }
        return signals;
    }

    // ── JS/CSS VERSION tekshirish ─────────────────────────────────────────────
    private checkJsCssVersions(html: string, raw: Record<string, string>): TechSignal[] {
        const signals: TechSignal[] = [];
        const $ = cheerio.load(html);

        $('script[src], link[rel="stylesheet"][href]').each((_, el) => {
            const src = $(el).attr('src') || $(el).attr('href') || '';
            if (!src) return;

            if (/\/wp-(includes|content)\//.test(src)) {
                const ver = src.match(/[?&]ver=([\d.]+)/)?.[1];
                if (ver) {
                    raw['wp_ver'] = src;
                    signals.push({ name: 'WordPress', version: ver, category: 'CMS', confidence: 88, method: 'JS/CSS ?ver=' });
                }
            }
            if (/\/bitrix\//.test(src)) {
                const ver = src.match(/[?&]v=([\d.]+)/)?.[1];
                raw['bitrix_ver'] = src;
                signals.push({ name: 'Bitrix', version: ver || null, category: 'CMS', confidence: 85, method: 'JS/CSS Bitrix path' });
            }
        });

        return signals;
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
            { pattern: /Hugo\s*([\d.]*)/i, name: 'Hugo', category: 'Static' },
            { pattern: /Jekyll\s*([\d.]*)/i, name: 'Jekyll', category: 'Static' },
            { pattern: /Gatsby\s*([\d.]*)/i, name: 'Gatsby', category: 'Static' },
            { pattern: /Next\.js\s*([\d.]*)/i, name: 'Next.js', category: 'Framework' },
            { pattern: /Nuxt\s*([\d.]*)/i, name: 'Nuxt.js', category: 'Framework' },
            { pattern: /Astro\s*([\d.]*)/i, name: 'Astro', category: 'Static' },
        ];

        for (const { pattern, name, category } of matchers) {
            const match = generator.match(pattern);
            if (match) {
                signals.push({ name, version: match[1]?.trim() || null, category, confidence: 95, method: 'meta generator tag' });
            }
        }
        return signals;
    }

    // ── UNIVERSAL PATTERN CHECKER ─────────────────────────────────────────────
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
            if (matched) {
                signals.push({
                    name: tech.name, version, category,
                    confidence: category === 'CMS' ? 85 : 78,
                    method: 'HTML/Header pattern',
                });
            }
        }
        return signals;
    }

    // ── CMS FILE PROBES ───────────────────────────────────────────────────────
    private async checkCmsFileProbes(baseUrl: string, raw: Record<string, string>): Promise<TechSignal[]> {
        const probes: Array<{ path: string; name: string; extractor: (b: string) => string | null }> = [];
        for (const cms of this.CMS_PATTERNS) {
            for (const fp of cms.fileProbes || []) probes.push({ path: fp.path, name: cms.name, extractor: fp.extractor });
        }

        const results = await Promise.allSettled(
            probes.map(async (probe) => {
                const res = await this.fetchPage(baseUrl + probe.path);
                if (!res || res.status >= 400) return null;
                const version = probe.extractor(res.html);
                if (!version) return null;
                raw[`file_${probe.name}_${probe.path}`] = res.html.slice(0, 150);
                return {
                    name: probe.name, version: version === 'detected' ? null : version,
                    category: 'CMS' as SiteCategory, confidence: 92, method: `File: ${probe.path}`,
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
    ): CmsDetectionResult {
        if (!signals.length) {
            return { url, cms: null, version: null, category: 'Unknown', confidence: 0, detectionMethod: [], detectedAt: new Date(), rawSignals, serverTech, jsFrameworks, httpStatus };
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
            return { url, cms: null, version: null, category: 'Custom', confidence: 0, detectionMethod: ['No known tech detected'], detectedAt: new Date(), rawSignals, serverTech, jsFrameworks, httpStatus };
        }

        return {
            url, cms: topName,
            version: this.resolveVersion(data.versions),
            category: data.category,
            confidence: Math.min(data.total, 100),
            detectionMethod: [...new Set(data.methods)],
            detectedAt: new Date(), rawSignals, serverTech, jsFrameworks, httpStatus,
        };
    }

    private resolveVersion(versions: string[]): string | null {
        if (!versions.length) return null;
        return versions.sort((a, b) => b.split('.').length - a.split('.').length)[0];
    }

    private async fetchPage(url: string): Promise<{ html: string; headers: Record<string, string>; status: number } | null> {
        try {
            const res: AxiosResponse = await axios.get(url, {
                timeout: 12000,
                maxRedirects: 5,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'uz-UZ,uz;q=0.9,en-US;q=0.8,en;q=0.7,ru;q=0.6',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                },
                validateStatus: () => true,
            });
            return {
                html: typeof res.data === 'string' ? res.data : JSON.stringify(res.data),
                headers: res.headers as Record<string, string>,
                status: res.status,
            };
        } catch { return null; }
    }

    private normalizeUrl(url: string): string {
        if (!url.startsWith('http')) url = 'https://' + url;
        return url.replace(/\/$/, '');
    }
}