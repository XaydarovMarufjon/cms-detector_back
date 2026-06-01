import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import * as cheerio from 'cheerio';

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

export interface CrawledImage {
  imageUrl: string;
  pageUrl: string;
}

export interface CrawlOptions {
  maxPages?: number;
  maxImages?: number;
  pageDelayMs?: number;
}

@Injectable()
export class ImageCrawlerService {
  private readonly logger = new Logger(ImageCrawlerService.name);

  /** Fetch homepage HTML and return unique absolute image URLs. */
  async extractHomepageImages(siteUrl: string): Promise<string[]> {
    const images = await this.extractSiteImages(siteUrl, { maxPages: 1, maxImages: Number.MAX_SAFE_INTEGER });
    return images.map(image => image.imageUrl);
  }

  /** Crawl same-site pages and return unique absolute image URLs with source page. */
  async extractSiteImages(siteUrl: string, options: CrawlOptions = {}): Promise<CrawledImage[]> {
    const normalized = this.normalize(siteUrl);
    const root = new URL(normalized);
    const maxPages = Math.max(1, options.maxPages ?? 200);
    const maxImages = Math.max(1, options.maxImages ?? 2_000);
    const pageDelayMs = Math.max(0, options.pageDelayMs ?? 150);

    const queue: string[] = [this.pageKey(root)];
    const queued = new Set(queue);
    const visited = new Set<string>();
    const images = new Map<string, CrawledImage>();

    while (queue.length && visited.size < maxPages && images.size < maxImages) {
      const pageUrl = queue.shift()!;
      if (visited.has(pageUrl)) continue;
      visited.add(pageUrl);

      const html = await this.fetchHtml(pageUrl);
      if (!html) continue;

      const $ = cheerio.load(html);
      this.collectImages($, pageUrl, images, maxImages);
      if (images.size < maxImages) {
        this.collectLinks($, pageUrl, root, queued, visited, queue, maxPages);
      }

      if (pageDelayMs > 0 && queue.length && visited.size < maxPages) {
        await this.sleep(pageDelayMs);
      }
    }

    this.logger.log(`image crawl ${normalized}: ${visited.size} page(s), ${images.size} image(s)`);
    return [...images.values()];
  }

  private collectImages(
    $: ReturnType<typeof cheerio.load>,
    pageUrl: string,
    found: Map<string, CrawledImage>,
    maxImages: number,
  ) {
    const add = (raw?: string | null) => {
      if (!raw || found.size >= maxImages) return;
      const abs = this.toImageUrl(raw, pageUrl);
      if (abs && !found.has(abs)) found.set(abs, { imageUrl: abs, pageUrl });
    };

    $('img').each((_, el) => {
      [
        'src',
        'data-src',
        'data-lazy-src',
        'data-original',
        'data-url',
        'data-img',
      ].forEach(attr => add($(el).attr(attr)));
      this.addSrcset($(el).attr('srcset') || $(el).attr('data-srcset'), add);
    });

    $('source').each((_, el) => {
      this.addSrcset($(el).attr('srcset') || $(el).attr('data-srcset'), add);
    });

    $('meta[property="og:image"], meta[name="twitter:image"], meta[itemprop="image"]').each((_, el) => {
      add($(el).attr('content'));
    });

    $('link[as="image"], link[rel~="preload"], link[rel~="icon"], link[rel~="apple-touch-icon"]').each((_, el) => {
      add($(el).attr('href'));
    });

    $('[style]').each((_, el) => {
      const style = $(el).attr('style') || '';
      for (const match of style.matchAll(/url\(['"]?([^'")]+)['"]?\)/gi)) {
        add(match[1]);
      }
    });
  }

  private collectLinks(
    $: ReturnType<typeof cheerio.load>,
    pageUrl: string,
    root: URL,
    queued: Set<string>,
    visited: Set<string>,
    queue: string[],
    maxPages: number,
  ) {
    $('a[href]').each((_, el) => {
      if (queued.size >= maxPages) return;
      const href = $(el).attr('href');
      if (!href || /^(mailto:|tel:|javascript:|data:|blob:)/i.test(href)) return;
      try {
        const next = new URL(href, pageUrl);
        if (!['http:', 'https:'].includes(next.protocol)) return;
        if (!this.sameSite(next, root)) return;
        if (!this.looksLikeHtmlPage(next)) return;
        const key = this.pageKey(next);
        if (queued.has(key) || visited.has(key)) return;
        queued.add(key);
        queue.push(key);
      } catch {
        /* ignore malformed */
      }
    });
  }

  private addSrcset(srcset: string | undefined, add: (raw?: string | null) => void) {
    if (!srcset) return;
    srcset.split(',').forEach(part => {
      const url = part.trim().split(/\s+/)[0];
      add(url);
    });
  }

  private async fetchHtml(url: string): Promise<string | null> {
    try {
      const res = await axios.get<string>(url, {
        timeout: 15_000,
        maxRedirects: 5,
        validateStatus: () => true,
        responseType: 'text',
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
        },
      });
      if (res.status >= 200 && res.status < 400 && typeof res.data === 'string') {
        return res.data;
      }
      this.logger.warn(`fetchHtml ${url} → HTTP ${res.status}`);
      return null;
    } catch (e) {
      this.logger.warn(`fetchHtml failed ${url}: ${(e as Error).message}`);
      return null;
    }
  }

  private toImageUrl(raw: string, baseUrl: string): string | null {
    try {
      if (/^(data:|blob:|javascript:)/i.test(raw)) return null;
      const abs = new URL(raw, baseUrl);
      abs.hash = '';
      const href = abs.toString();
      return this.isImageUrl(href) ? href : null;
    } catch {
      return null;
    }
  }

  private isImageUrl(u: string): boolean {
    try {
      const url = new URL(u);
      const path = url.pathname.toLowerCase();
      return /\.(jpe?g|png|gif|webp|bmp|avif|tiff?|svg)$/i.test(path) ||
             /image|photo|picture|media/.test(path);
    } catch {
      return false;
    }
  }

  private normalize(url: string): string {
    if (!/^https?:\/\//i.test(url)) return `https://${url}`;
    return url;
  }

  private pageKey(url: URL | string): string {
    const u = typeof url === 'string' ? new URL(url) : new URL(url.toString());
    u.hash = '';
    return u.toString();
  }

  private sameSite(candidate: URL, root: URL): boolean {
    return this.hostKey(candidate.hostname) === this.hostKey(root.hostname);
  }

  private hostKey(hostname: string): string {
    return hostname.toLowerCase().replace(/^www\./, '');
  }

  private looksLikeHtmlPage(url: URL): boolean {
    const path = url.pathname.toLowerCase();
    if (path.includes('/wp-json/') || path.includes('/api/')) return false;
    const ext = path.match(/\.([a-z0-9]{1,8})$/)?.[1];
    if (!ext) return true;
    return ['html', 'htm', 'php', 'asp', 'aspx', 'jsp'].includes(ext);
  }

  private sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
