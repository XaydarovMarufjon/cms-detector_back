import type { SiteCategory } from './cms-detector.service';

export interface CmsDetectorFixture {
  name: string;
  url: string;
  html: string;
  headers?: Record<string, string>;
  expectedCms: string | null;
  expectedCategory: SiteCategory;
  minConfidence: number;
}

export const CMS_DETECTOR_FIXTURES: CmsDetectorFixture[] = [
  {
    name: 'wordpress strong asset and generator',
    url: 'https://example-wordpress.test',
    html: `
      <html>
        <head>
          <title>Example WP</title>
          <meta name="generator" content="WordPress 6.5.4">
          <link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css?ver=6.5.4">
        </head>
        <body><script src="/wp-includes/js/wp-embed.min.js?ver=6.5.4"></script></body>
      </html>
    `,
    expectedCms: 'WordPress',
    expectedCategory: 'CMS',
    minConfidence: 90,
  },
  {
    name: 'single marketing mention should stay unknown',
    url: 'https://example-copy.test',
    html: '<html><head><title>Copy</title></head><body>We migrate content from WordPress.</body></html>',
    expectedCms: null,
    expectedCategory: 'Unknown',
    minConfidence: 0,
  },
  {
    name: 'headless contentful in static app',
    url: 'https://headless.test',
    html: `
      <html>
        <head><title>Headless app</title></head>
        <body>
          <script>
            window.__config = { api: "https://cdn.contentful.com/spaces/abc/environments/master" };
          </script>
        </body>
      </html>
    `,
    expectedCms: 'Contentful',
    expectedCategory: 'Headless CMS',
    minConfidence: 42,
  },
  {
    name: 'nextjs app shell',
    url: 'https://next.test',
    html: `
      <html>
        <head><script id="__NEXT_DATA__" type="application/json">{}</script></head>
        <body><div id="__next"></div><script src="/_next/static/chunks/main.js"></script></body>
      </html>
    `,
    expectedCms: 'Next.js',
    expectedCategory: 'Fullstack Framework',
    minConfidence: 42,
  },
  {
    name: 'shopify global variable',
    url: 'https://shop.test',
    html: `
      <html>
        <body>
          <script>window.Shopify = { theme: { name: "Demo" } }; ShopifyAnalytics = {};</script>
          <script src="https://cdn.shopify.com/s/files/1/0000/theme.js"></script>
        </body>
      </html>
    `,
    expectedCms: 'Shopify',
    expectedCategory: 'E-commerce CMS',
    minConfidence: 90,
  },
  {
    name: 'woocommerce requires wordpress',
    url: 'https://commerce.test',
    html: `
      <html>
        <body class="woocommerce">
          <link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.9.1">
          <button class="wc-add-to-cart">Buy</button>
        </body>
      </html>
    `,
    expectedCms: 'WooCommerce',
    expectedCategory: 'E-commerce CMS',
    minConfidence: 86,
  },
  {
    name: 'angular dom fingerprint',
    url: 'https://angular.test',
    html: '<html><body><app-root ng-version="17.3.0"></app-root></body></html>',
    expectedCms: 'Angular',
    expectedCategory: 'Frontend Framework / SPA',
    minConfidence: 88,
  },
];
