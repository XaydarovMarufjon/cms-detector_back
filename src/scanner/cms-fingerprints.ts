export type SupplementalCategory =
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

export interface SupplementalFileProbe {
  name: string;
  category: SupplementalCategory;
  path: string;
  confidence: number;
  allowErrorStatus?: boolean;
  extractor: (body: string, status: number, headers: Record<string, string>) => string | null;
}

export interface BundleFingerprint {
  name: string;
  category: SupplementalCategory;
  confidence: number;
  patterns: RegExp[];
  versionPattern?: RegExp;
}

export interface WappalyzerStylePattern {
  regex: RegExp;
  confidence?: number;
  version?: string;
}

export interface WappalyzerStyleDomRule {
  selector: string;
  confidence?: number;
  text?: WappalyzerStylePattern[];
  attributes?: Record<string, WappalyzerStylePattern[]>;
}

export interface WappalyzerStyleFingerprint {
  name: string;
  category: SupplementalCategory;
  html?: WappalyzerStylePattern[];
  text?: WappalyzerStylePattern[];
  scriptSrc?: WappalyzerStylePattern[];
  scripts?: WappalyzerStylePattern[];
  headers?: Record<string, WappalyzerStylePattern[]>;
  cookies?: Record<string, WappalyzerStylePattern[]>;
  meta?: Record<string, WappalyzerStylePattern[]>;
  url?: WappalyzerStylePattern[];
  dom?: WappalyzerStyleDomRule[];
  implies?: Array<{ name: string; confidence?: number }>;
  requires?: string[];
  excludes?: string[];
}

const wp = (regex: RegExp, confidence = 85, version?: string): WappalyzerStylePattern => ({ regex, confidence, version });

export const STRONG_PATTERN_ONLY_TECHS = new Set([
  'Shopify',
  'Wix',
  'Squarespace',
  'Webflow',
  'Tilda',
  'Framer',
  'Google Sites',
  'Weebly',
  'Duda',
  'Blogger',
]);

export const WAPPALYZER_STYLE_FINGERPRINTS: WappalyzerStyleFingerprint[] = [
  {
    name: 'WordPress',
    category: 'CMS',
    html: [
      wp(/\/wp-content\//i, 85),
      wp(/\/wp-includes\//i, 85),
      wp(/wp-json/i, 82),
      wp(/wp-emoji-release\.min\.js\?ver=([\d.]+)/i, 90, '\\1'),
      wp(/<meta[^>]+generator[^>]+WordPress\s+([\d.]+)/i, 95, '\\1'),
    ],
    scriptSrc: [
      wp(/\/wp-(?:includes|content)\/.*?[?&]ver=([\d.]+)/i, 88, '\\1'),
      wp(/\/wp-(?:includes|content)\//i, 82),
    ],
    cookies: {
      wordpress_: [wp(/.+/i, 88)],
      wordpress_logged_in: [wp(/.+/i, 90)],
      'wp-settings-': [wp(/.+/i, 84)],
    },
    meta: {
      generator: [wp(/WordPress\s*([\d.]*)/i, 95, '\\1')],
    },
    url: [wp(/\/wp-json\/?$/i, 82)],
    implies: [{ name: 'PHP', confidence: 45 }],
  },
  {
    name: 'WooCommerce',
    category: 'E-commerce CMS',
    html: [
      wp(/woocommerce/i, 94),
      wp(/class=["'][^"']*woocommerce/i, 96),
      wp(/wc-add-to-cart/i, 94),
    ],
    scriptSrc: [wp(/\/woocommerce\/|wc-(?:add-to-cart|cart-fragments)/i, 96)],
    cookies: {
      woocommerce_items_in_cart: [wp(/.+/i, 96)],
      wp_woocommerce_session: [wp(/.+/i, 96)],
    },
    requires: ['WordPress'],
  },
  {
    name: 'Elementor',
    category: 'CMS',
    html: [wp(/elementor-/i, 78), wp(/elementorFrontendConfig/i, 82)],
    scriptSrc: [wp(/\/elementor\/assets\//i, 82)],
    requires: ['WordPress'],
    implies: [{ name: 'WordPress', confidence: 50 }],
  },
  {
    name: 'Shopify',
    category: 'E-commerce CMS',
    html: [wp(/Shopify\.theme/i, 92), wp(/cdn\.shopify\.com/i, 88), wp(/myshopify\.com/i, 86)],
    scriptSrc: [wp(/cdn\.shopify\.com/i, 90), wp(/shopifycloud/i, 86)],
    scripts: [wp(/\bShopify\s*=/i, 92), wp(/ShopifyAnalytics/i, 86)],
    headers: {
      'x-shopid': [wp(/.+/i, 94)],
      'x-shopify-stage': [wp(/.+/i, 92)],
    },
    cookies: {
      _shopify_: [wp(/.+/i, 90)],
      cart_currency: [wp(/.+/i, 84)],
    },
  },
  {
    name: 'Joomla',
    category: 'CMS',
    html: [wp(/\/components\/com_/i, 84), wp(/\/media\/system\/js\//i, 84), wp(/Joomla!\s*([\d.]*)/i, 92, '\\1')],
    scriptSrc: [wp(/\/media\/(?:jui|system)\//i, 85)],
    meta: {
      generator: [wp(/Joomla!\s*([\d.]*)/i, 95, '\\1')],
    },
    cookies: {
      joomla_user_state: [wp(/.+/i, 88)],
    },
    implies: [{ name: 'PHP', confidence: 45 }],
  },
  {
    name: 'Drupal',
    category: 'CMS',
    html: [wp(/Drupal\.settings/i, 90), wp(/\/core\/misc\/drupal\.js/i, 86), wp(/data-drupal-/i, 84)],
    scriptSrc: [wp(/\/core\/misc\/drupal\.js/i, 88), wp(/\/sites\/(?:all|default)\//i, 84)],
    headers: {
      'x-generator': [wp(/Drupal\s*([\d.]*)/i, 94, '\\1')],
    },
    meta: {
      generator: [wp(/Drupal\s*([\d.]*)/i, 95, '\\1')],
    },
    cookies: {
      SESS: [wp(/[a-f0-9]{16,}/i, 82)],
      SSESS: [wp(/[a-f0-9]{16,}/i, 84)],
    },
    implies: [{ name: 'PHP', confidence: 45 }],
  },
  {
    name: 'Bitrix',
    category: 'CMS',
    html: [wp(/\/bitrix\//i, 86), wp(/BX\.(?:ready|message)/i, 88), wp(/bitrix_sessid/i, 88)],
    scriptSrc: [wp(/\/bitrix\//i, 88)],
    headers: {
      'x-powered-cms': [wp(/bitrix/i, 94)],
    },
    cookies: {
      BITRIX_SM_: [wp(/.+/i, 90)],
      BX_USER_ID: [wp(/.+/i, 86)],
    },
    implies: [{ name: 'PHP', confidence: 45 }],
  },
  {
    name: 'Magento',
    category: 'E-commerce CMS',
    html: [wp(/Magento_/i, 84), wp(/\/pub\/static\//i, 82), wp(/Mage\.Cookies/i, 88), wp(/Magento\/([\d.]+)/i, 92, '\\1')],
    scriptSrc: [wp(/\/pub\/static\//i, 84), wp(/requirejs\/require/i, 76)],
    headers: {
      'x-magento-vary': [wp(/.+/i, 92)],
      'x-magento-cache-debug': [wp(/.+/i, 86)],
    },
    cookies: {
      mage_cache_storage: [wp(/.+/i, 86)],
      mage_messages: [wp(/.+/i, 86)],
    },
  },
  {
    name: 'OpenCart',
    category: 'E-commerce CMS',
    html: [wp(/route=common\//i, 82), wp(/catalog\/view\/theme/i, 84), wp(/index\.php\?route=/i, 82)],
    cookies: {
      OCSESSID: [wp(/.+/i, 88)],
    },
    implies: [{ name: 'PHP', confidence: 45 }],
  },
  {
    name: 'PrestaShop',
    category: 'E-commerce CMS',
    html: [wp(/prestashop/i, 84), wp(/\/modules\/ps_/i, 84), wp(/var prestashop/i, 88)],
    cookies: {
      PrestaShop: [wp(/.+/i, 88)],
    },
    implies: [{ name: 'PHP', confidence: 45 }],
  },
  {
    name: 'Laravel',
    category: 'Backend Framework',
    html: [wp(/csrf-token/i, 62)],
    headers: {
      'x-powered-by': [wp(/PHP/i, 45)],
    },
    cookies: {
      laravel_session: [wp(/.+/i, 88)],
      'XSRF-TOKEN': [wp(/.+/i, 72)],
    },
    implies: [{ name: 'PHP', confidence: 55 }],
  },
  {
    name: 'Next.js',
    category: 'Fullstack Framework',
    html: [wp(/__NEXT_DATA__/i, 90), wp(/\/_next\/static\//i, 88)],
    scriptSrc: [wp(/\/_next\/static\//i, 90)],
    headers: {
      'x-powered-by': [wp(/Next\.js\s*([\d.]*)/i, 90, '\\1')],
      'x-nextjs-cache': [wp(/.+/i, 84)],
    },
  },
  {
    name: 'Nuxt.js',
    category: 'Fullstack Framework',
    html: [wp(/__NUXT__/i, 90), wp(/\/_nuxt\//i, 88)],
    scriptSrc: [wp(/\/_nuxt\//i, 90)],
  },
  {
    name: 'React',
    category: 'Frontend Framework / SPA',
    html: [wp(/react-dom/i, 74), wp(/__reactFiber/i, 82)],
    scripts: [wp(/ReactDOM\.(?:render|createRoot)/i, 82)],
  },
  {
    name: 'Vue',
    category: 'Frontend Framework / SPA',
    html: [wp(/\bdata-v-[a-f0-9]+/i, 76), wp(/vue\.js/i, 76)],
    scripts: [wp(/createApp\(|new Vue\(/i, 82)],
  },
  {
    name: 'Angular',
    category: 'Frontend Framework / SPA',
    html: [wp(/ng-version/i, 88), wp(/_ngcontent-/i, 80)],
    dom: [{ selector: '[ng-version]', confidence: 90 }],
  },
  {
    name: 'Contentful',
    category: 'Headless CMS',
    html: [wp(/cdn\.contentful\.com/i, 84), wp(/ctfassets\.net/i, 82)],
    scripts: [wp(/contentful/i, 82)],
  },
  {
    name: 'Sanity',
    category: 'Headless CMS',
    html: [wp(/cdn\.sanity\.io/i, 84), wp(/sanity\.io/i, 78)],
    scripts: [wp(/sanityClient|createClient\(\{[^}]*projectId/i, 84)],
  },
  {
    name: 'Strapi',
    category: 'Headless CMS',
    html: [wp(/strapi/i, 78)],
    scripts: [wp(/\/api\/(?:articles|pages|posts|upload)\b/i, 80)],
  },
  {
    name: 'Directus',
    category: 'Headless CMS',
    html: [wp(/directus/i, 78)],
    scripts: [wp(/\/items\/[A-Za-z0-9_-]+/i, 80)],
  },
];

export const SUPPLEMENTAL_CMS_FILE_PROBES: SupplementalFileProbe[] = [
  {
    name: 'WordPress',
    category: 'CMS',
    path: '/wp-admin/install.php',
    confidence: 90,
    extractor: body => /WordPress|wp-admin|wp-submit|install\.php/i.test(body) ? 'detected' : null,
  },
  {
    name: 'Joomla',
    category: 'CMS',
    path: '/administrator/index.php',
    confidence: 90,
    extractor: body => /Joomla|com_login|mod-login|administrator\/templates/i.test(body) ? 'detected' : null,
  },
  {
    name: 'Drupal',
    category: 'CMS',
    path: '/user/login',
    confidence: 88,
    extractor: body => /Drupal|data-drupal-selector|user-login-form|\/core\/misc\//i.test(body) ? 'detected' : null,
  },
  {
    name: 'OpenCart',
    category: 'E-commerce CMS',
    path: '/admin/index.php',
    confidence: 88,
    extractor: body => /OpenCart|common\/login|route=common\/login|catalog\/view/i.test(body) ? 'detected' : null,
  },
  {
    name: 'PrestaShop',
    category: 'E-commerce CMS',
    path: '/admin-dev/index.php',
    confidence: 86,
    extractor: body => /PrestaShop|AdminLogin|prestashop/i.test(body) ? 'detected' : null,
  },
  {
    name: 'Magento',
    category: 'E-commerce CMS',
    path: '/admin/',
    confidence: 84,
    extractor: body => /Magento|mage-|form_key|adminhtml/i.test(body) ? 'detected' : null,
  },
  {
    name: 'Bitrix',
    category: 'CMS',
    path: '/bitrix/admin/',
    confidence: 90,
    extractor: body => /Bitrix|BX\.|bitrix_sessid|bx-admin/i.test(body) ? 'detected' : null,
  },
  {
    name: 'MODX',
    category: 'CMS',
    path: '/manager/index.php',
    confidence: 88,
    extractor: body => /MODX|modx-login|manager\/templates/i.test(body) ? 'detected' : null,
  },
];

export const JS_BUNDLE_FINGERPRINTS: BundleFingerprint[] = [
  {
    name: 'WordPress',
    category: 'CMS',
    confidence: 82,
    patterns: [/wp-json/i, /wp-content/i, /wp-includes/i],
    versionPattern: /wp-(?:includes|content)[^"']*[?&]ver=([\d.]+)/i,
  },
  {
    name: 'Shopify',
    category: 'E-commerce CMS',
    confidence: 86,
    patterns: [/cdn\.shopify\.com/i, /Shopify\.theme/i, /myshopify\.com/i],
  },
  {
    name: 'Contentful',
    category: 'Headless CMS',
    confidence: 82,
    patterns: [/cdn\.contentful\.com/i, /contentful_space_id/i, /contentful/i],
  },
  {
    name: 'Sanity',
    category: 'Headless CMS',
    confidence: 82,
    patterns: [/cdn\.sanity\.io/i, /sanityClient/i, /projectId[^A-Za-z0-9]+dataset/i],
  },
  {
    name: 'Strapi',
    category: 'Headless CMS',
    confidence: 82,
    patterns: [/\/api\/(?:articles|pages|posts|upload)\b/i, /strapi/i],
  },
  {
    name: 'Directus',
    category: 'Headless CMS',
    confidence: 82,
    patterns: [/directus/i, /\/items\/[A-Za-z0-9_-]+/i],
  },
  {
    name: 'Payload CMS',
    category: 'Headless CMS',
    confidence: 82,
    patterns: [/payloadcms/i, /\/api\/globals\//i, /\/api\/collections\//i],
  },
  {
    name: 'Hygraph',
    category: 'Headless CMS',
    confidence: 80,
    patterns: [/hygraph\.com/i, /graphcms/i],
  },
  {
    name: 'Storyblok',
    category: 'Headless CMS',
    confidence: 80,
    patterns: [/storyblok/i, /api\.storyblok\.com/i],
  },
  {
    name: 'Next.js',
    category: 'Fullstack Framework',
    confidence: 78,
    patterns: [/__NEXT_DATA__/i, /\/_next\/static\//i],
  },
  {
    name: 'Nuxt.js',
    category: 'Fullstack Framework',
    confidence: 78,
    patterns: [/__NUXT__/i, /\/_nuxt\//i],
  },
];
