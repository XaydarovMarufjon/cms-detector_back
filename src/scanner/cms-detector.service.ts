import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';

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
    pageTitle: string | null;
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

    private readonly proxies: string[] = (process.env['PROXY_LIST'] || '')
        .split(',').map(p => p.trim()).filter(Boolean);
    private proxyIndex = 0;

    private getNextAgent(): any {
        if (!this.proxies.length) return undefined;
        const proxy = this.proxies[this.proxyIndex % this.proxies.length];
        this.proxyIndex++;
        if (proxy.startsWith('socks4://') || proxy.startsWith('socks5://')) return new SocksProxyAgent(proxy);
        return new HttpsProxyAgent(proxy);
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
                /"wp_version":"([\d.]+)"/i,
            ],
            cookieKeys: [/wordpress_/i, /wordpress_logged_in/i, /wp-settings-/i],
            fileProbes: [
                {
                    path: '/wp-json/',
                    extractor: b => {
                        try {
                            const j = JSON.parse(b);
                            return (j?.generator?.match(/WordPress\/([\d.]+)/i)?.[1]) ||
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
                    extractor: b => b.match(/Version\s+([\d.]+)/i)?.[1] || null,
                },
                {
                    path: '/wp-login.php',
                    extractor: b => {
                        const ver = b.match(/ver=([\d.]+)/)?.[1];
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
                /"bitrix_sessid".*?"version"\s*:\s*"([\d.]+)"/i,
                /BX\.message\(\{[^}]*"version"\s*:\s*"([\d.]+)"/i,
            ],
            cookieKeys: [/BITRIX_SM_/i, /BX_USER_ID/i],
            headerKeys: [
                { key: 'x-powered-cms', pattern: /bitrix/i },
                { key: 'set-cookie', pattern: /BITRIX_SM/i },
            ],
            fileProbes: [
                {
                    path: '/bitrix/modules/main/install/version.php',
                    extractor: b => b.match(/VERSION\s*=\s*["']([\d.]+)["']/i)?.[1] || null,
                },
                {
                    path: '/bitrix/admin/',
                    extractor: b => {
                        const ver = b.match(/ver=([\d.]+)/)?.[1];
                        return b.includes('Bitrix') ? (ver || 'detected') : null;
                    },
                },
                {
                    path: '/bitrix/js/main/core/core.js',
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
            versionPatterns: [/"version":"([\d.]+)"/i],
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
            ],
        },
        {
            name: 'MODX',
            patterns: [
                /powered by MODX/i, /modx\.com/i, /\/assets\/components\//i,
                /\/assets\/snippets\//i, /MODx/i, /modxcloud/i,
                /class="modx/i, /modx\.reloadPage/i,
            ],
            fileProbes: [
                {
                    path: '/manager/',
                    extractor: b => {
                        const ver = b.match(/MODX\s*([\d.]+)/i)?.[1];
                        return (b.includes('MODX') || b.includes('modx')) ? (ver || 'detected') : null;
                    },
                },
                {
                    path: '/core/cache/mgr/web/config.cache.php',
                    extractor: b => b.match(/modx_version.*?([\d.]+)/i)?.[1] || null,
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
            patterns: [/route=common\//i, /opencart/i, /catalog\/view\/theme/i, /index\.php\?route=/i],
            fileProbes: [
                {
                    path: '/index.php?route=common/home',
                    extractor: b => b.includes('OpenCart') ? 'detected' : null,
                },
                {
                    path: '/CHANGELOG.md',
                    extractor: b => b.match(/##\s*([\d.]+)/)?.[1] || null,
                },
            ],
        },
        {
            name: 'PrestaShop',
            patterns: [/prestashop/i, /\/themes\/classic\//i, /id_product=/i, /prestashop\.com/i],
            cookieKeys: [/PrestaShop-/i, /PHPSESSID/i],
            fileProbes: [
                {
                    path: '/modules/paypal/package.json',
                    extractor: () => null,
                },
                {
                    path: '/app/version.php',
                    extractor: b => b.match(/'([\d.]+)'/)?.[1] || null,
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
    ];

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
    ];

    // ── MAIN ─────────────────────────────────────────────────────────────────
    async detect(url: string): Promise<CmsDetectionResult> {
        const baseUrl = this.normalizeUrl(url);
        const signals: TechSignal[] = [];
        const rawSignals: Record<string, string> = {};
        let serverTech: string[] = [];
        let jsFrameworks: string[] = [];
        let httpStatus: number | null = null;
        let pageTitle: string | null = null;

        try {
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

                // Extract page title from <title> tag
                const $ = cheerio.load(main.html);
                const rawTitle = $('title').first().text().trim();
                pageTitle = rawTitle || null;

                signals.push(...this.checkPatternGroup(main.html, main.headers, this.CMS_PATTERNS, 'CMS', rawSignals));
                signals.push(...this.checkPatternGroup(main.html, main.headers, this.FRAMEWORK_PATTERNS, 'Framework', rawSignals));
                signals.push(...this.checkPatternGroup(main.html, main.headers, this.HEADLESS_PATTERNS, 'Headless', rawSignals));
                signals.push(...this.checkPatternGroup(main.html, main.headers, this.STATIC_PATTERNS, 'Static', rawSignals));
                signals.push(...this.checkMetaGenerator(main.html, rawSignals));
                signals.push(...this.checkJsCssVersions(main.html, rawSignals));
                signals.push(...this.checkHtmlComments(main.html, rawSignals));
                signals.push(...this.checkCookies(main.headers, rawSignals));
                signals.push(...this.checkInlineVersionPatterns(main.html, rawSignals));
            }

            if (robots?.html) signals.push(...this.checkRobotsTxt(robots.html, rawSignals));
            if (sitemap?.html) signals.push(...this.checkSitemap(sitemap.html, rawSignals));

            signals.push(...await this.checkCmsFileProbes(baseUrl, rawSignals));

        } catch (err) {
            this.logger.warn(`Detection failed for ${url}: ${String(err)}`);
        }

        return this.resolveResult(baseUrl, signals, rawSignals, serverTech, jsFrameworks, httpStatus, pageTitle);
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
            { re: /laravel_session/i, name: 'Laravel', category: 'Framework', confidence: 85 },
            { re: /XSRF-TOKEN/i, name: 'Laravel', category: 'Framework', confidence: 70 },
            { re: /_shopify_/i, name: 'Shopify', category: 'CMS', confidence: 92 },
            { re: /PrestaShop/i, name: 'PrestaShop', category: 'CMS', confidence: 85 },
            { re: /ss_cvr/i, name: 'Squarespace', category: 'CMS', confidence: 85 },
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
            { re: /wordpress\.org\/\?v=([\d.]+)/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            { re: /wp-emoji-release\.min\.js\?ver=([\d.]+)/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            { re: /var\s+_wpVersion\s*=\s*['"]([^'"]+)['"]/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            { re: /"version":"([\d.]+)"[^}]*"name":"WordPress"/i, name: 'WordPress', category: 'CMS', verIdx: 1 },
            { re: /BX\.message\([^)]*"version"\s*:\s*"([\d.]+)"/i, name: 'Bitrix', category: 'CMS', verIdx: 1 },
            { re: /Ghost\s+v?([\d.]+)/i, name: 'Ghost', category: 'CMS', verIdx: 1 },
            { re: /typo3\/js\/[^'"]*\?[^'"]*v=([\d.]+)/i, name: 'TYPO3', category: 'CMS', verIdx: 1 },
            { re: /"django":\s*"([\d.]+)"/i, name: 'Django', category: 'Framework', verIdx: 1 },
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
        ];

        for (const { pattern, name, category } of checks) {
            if (pattern.test(body)) {
                signals.push({ name, version: null, category, confidence: 70, method: 'robots.txt' });
            }
        }
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
            { pattern: /PrestaShop\s*([\d.]*)/i, name: 'PrestaShop', category: 'CMS' },
            { pattern: /Hugo\s*([\d.]*)/i, name: 'Hugo', category: 'Static' },
            { pattern: /Jekyll\s*([\d.]*)/i, name: 'Jekyll', category: 'Static' },
            { pattern: /Gatsby\s*([\d.]*)/i, name: 'Gatsby', category: 'Static' },
            { pattern: /Next\.js\s*([\d.]*)/i, name: 'Next.js', category: 'Framework' },
            { pattern: /Nuxt\s*([\d.]*)/i, name: 'Nuxt.js', category: 'Framework' },
            { pattern: /Astro\s*([\d.]*)/i, name: 'Astro', category: 'Static' },
            { pattern: /October\s*([\d.]*)/i, name: 'OctoberCMS', category: 'CMS' },
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
            let version: string | null = null;

            for (const pattern of tech.patterns || []) {
                if (pattern.test(html)) {
                    matchCount++;
                    raw[`html_${tech.name}_${matchCount}`] = pattern.toString();
                }
            }

            for (const hk of tech.headerKeys || []) {
                const val = headers[hk.key.toLowerCase()] || '';
                if (hk.pattern.test(val)) {
                    matchCount++;
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
                signals.push({
                    name: tech.name, version, category,
                    confidence: baseConf + bonus,
                    method: `Pattern (${matchCount} match)`,
                });
            }
        }
        return signals;
    }

    // ── FILE PROBES ───────────────────────────────────────────────────────────
    private async checkCmsFileProbes(baseUrl: string, raw: Record<string, string>): Promise<TechSignal[]> {
        const probes: Array<{ path: string; name: string; extractor: (b: string) => string | null }> = [];
        for (const cms of this.CMS_PATTERNS) {
            for (const fp of cms.fileProbes || []) {
                probes.push({ path: fp.path, name: cms.name, extractor: fp.extractor });
            }
        }

        const results = await Promise.allSettled(
            probes.map(async (probe) => {
                const res = await this.fetchPage(baseUrl + probe.path);
                if (!res || res.status >= 400) return null;
                const version = probe.extractor(res.html);
                if (!version) return null;
                raw[`file_${probe.name}_${probe.path}`] = res.html.slice(0, 150);
                return {
                    name: probe.name,
                    version: version === 'detected' ? null : version,
                    category: 'CMS' as SiteCategory,
                    confidence: version !== 'detected' ? 95 : 88,
                    method: `File probe: ${probe.path}`,
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
    ): CmsDetectionResult {
        if (!signals.length) {
            return { url, cms: null, version: null, category: 'Unknown', confidence: 0, detectionMethod: [], detectedAt: new Date(), rawSignals, serverTech, jsFrameworks, httpStatus, pageTitle };
        }

        const scores: Record<string, { max: number; versions: string[]; methods: string[]; category: SiteCategory; evidenceTypes: Set<string> }> = {};

        for (const s of signals) {
            if (!scores[s.name]) scores[s.name] = { max: 0, versions: [], methods: [], category: s.category, evidenceTypes: new Set() };
            // Keep the highest single-signal confidence (no summing)
            if (s.confidence > scores[s.name].max) scores[s.name].max = s.confidence;
            if (s.version) scores[s.name].versions.push(s.version);
            scores[s.name].methods.push(s.method);
            // Track distinct evidence category for bonus calculation
            const eType = s.method.startsWith('File probe') || s.method.startsWith('RSS')
                ? 'file'
                : s.method === 'meta generator'   ? 'meta'
                : s.method === 'Cookie'            ? 'cookie'
                : s.method === 'Inline version'    ? 'inline'
                : s.method.startsWith('Header')    ? 'header'
                : s.method.startsWith('Asset') || s.method.includes('asset') ? 'asset'
                : s.method.includes('robots') || s.method.includes('sitemap') ? 'crawl'
                : s.method.includes('HTML comment') ? 'comment'
                : 'pattern';
            scores[s.name].evidenceTypes.add(eType);
        }

        // Sort by (max confidence + evidence-type bonus) descending
        const sorted = Object.entries(scores).sort((a, b) => {
            const scoreA = a[1].max + Math.min((a[1].evidenceTypes.size - 1) * 6, 18);
            const scoreB = b[1].max + Math.min((b[1].evidenceTypes.size - 1) * 6, 18);
            return scoreB - scoreA;
        });
        const [topName, data] = sorted[0];

        // Require at least 40 base confidence to report a CMS
        if (data.max < 40) {
            return { url, cms: null, version: null, category: 'Custom', confidence: 0, detectionMethod: ['No known tech detected'], detectedAt: new Date(), rawSignals, serverTech, jsFrameworks, httpStatus, pageTitle };
        }

        // Versiyani tanlash: file probe/inline > meta generator > asset URL
        const version = this.resolveVersion(data.versions, signals.filter(s => s.name === topName));

        // Final confidence: best signal + bonus per additional independent evidence type, cap 97
        const typeBonus = Math.min((data.evidenceTypes.size - 1) * 6, 18);
        const finalConfidence = Math.min(data.max + typeBonus, 97);

        return {
            url, cms: topName,
            version,
            category: data.category,
            confidence: finalConfidence,
            detectionMethod: [...new Set(data.methods)],
            detectedAt: new Date(), rawSignals, serverTech, jsFrameworks, httpStatus, pageTitle,
        };
    }

    private resolveVersion(versions: string[], signals: TechSignal[]): string | null {
        if (!versions.length) return null;

        // Eng ishonchli manba tartibida versiya tanlash
        const priority = ['File probe', 'meta generator', 'Inline version', 'Asset ?ver=', 'RSS feed'];
        for (const p of priority) {
            const s = signals.find(sig => sig.version && sig.method.includes(p.split(' ')[0]));
            if (s?.version) return s.version;
        }

        // Fallback: eng uzun versiya (ko'proq raqam = aniqroq)
        return versions.sort((a, b) => b.split('.').length - a.split('.').length)[0];
    }

    // ── FETCH PAGE ────────────────────────────────────────────────────────────
    private async fetchPage(url: string): Promise<{ html: string; headers: Record<string, string>; status: number } | null> {
        const agent = this.getNextAgent();
        try {
            const res: AxiosResponse = await axios.get(url, {
                timeout: 12000,
                maxRedirects: 5,
                ...(agent ? { httpAgent: agent, httpsAgent: agent } : {}),
                headers: {
                    'User-Agent': this.randomUserAgent(),
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

    private readonly USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
    ];

    private randomUserAgent(): string {
        return this.USER_AGENTS[Math.floor(Math.random() * this.USER_AGENTS.length)];
    }

    private normalizeUrl(url: string): string {
        if (!url.startsWith('http')) url = 'https://' + url;
        return url.replace(/\/$/, '');
    }
}
