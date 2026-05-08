import { Injectable } from '@nestjs/common';
import * as tls from 'tls';
import axios from 'axios';
import { AlertsService } from '../alerts/alerts.service';

export interface SslInfo {
  valid:       boolean;
  issuer:      string | null;
  subject:     string | null;
  validFrom:   string | null;
  validTo:     string | null;
  daysLeft:    number | null;
  selfSigned:  boolean;
}

export interface GeoInfo {
  country:     string | null;
  countryCode: string | null;
  city:        string | null;
  region:      string | null;
  isp:         string | null;
  org:         string | null;
  timezone:    string | null;
}

export interface SecHeadersInfo {
  hsts:                 boolean;
  csp:                  boolean;
  xFrameOptions:        boolean;
  xContentTypeOptions:  boolean;
  xXssProtection:       boolean;
  referrerPolicy:       boolean;
  permissionsPolicy:    boolean;
  coopPolicy:           boolean;
  coepPolicy:           boolean;
  corpPolicy:           boolean;
  score:                number;   // 0-100
  grade:                string;   // A+ … F
  present:              string[];
  missing:              string[];
}

export interface SiteInfoData {
  ssl:     SslInfo | null;
  geo:     GeoInfo | null;
  headers: SecHeadersInfo | null;
}

const SEC_HEADERS: { key: string; name: string; points: number }[] = [
  { key: 'strict-transport-security',      name: 'HSTS',                        points: 17 },
  { key: 'content-security-policy',        name: 'CSP',                         points: 17 },
  { key: 'x-content-type-options',         name: 'X-Content-Type-Options',      points: 12 },
  { key: 'x-frame-options',                name: 'X-Frame-Options',             points: 10 },
  { key: 'referrer-policy',                name: 'Referrer-Policy',             points: 10 },
  { key: 'permissions-policy',             name: 'Permissions-Policy',          points:  8 },
  { key: 'cross-origin-opener-policy',     name: 'Cross-Origin-Opener-Policy',  points:  8 },
  { key: 'cross-origin-embedder-policy',   name: 'Cross-Origin-Embedder-Policy', points: 8 },
  { key: 'cross-origin-resource-policy',   name: 'Cross-Origin-Resource-Policy', points: 6 },
  { key: 'x-xss-protection',              name: 'X-XSS-Protection',            points:  4 },
];

@Injectable()
export class SiteInfoService {
  private readonly cache = new Map<string, { data: SiteInfoData; exp: number }>();
  private readonly TTL = 60 * 60 * 1000; // 1h

  constructor(private readonly alertsService: AlertsService) {}

  async analyze(url: string, websiteId?: string): Promise<SiteInfoData> {
    const hostname = this.extractHost(url);
    if (!hostname) return { ssl: null, geo: null, headers: null };

    const cached = this.cache.get(hostname);
    if (cached && Date.now() < cached.exp) return cached.data;

    const [ssl, headersRaw, geo] = await Promise.all([
      this.checkSsl(hostname),
      this.fetchHeaders(url),
      this.fetchGeo(hostname),
    ]);

    const headers = headersRaw ? this.analyzeHeaders(headersRaw) : null;

    // Fire SSL alert if expiry is within 90 days
    if (ssl?.validTo && ssl.daysLeft !== null) {
      this.alertsService.checkSslExpiry(hostname, ssl.daysLeft, ssl.validTo, websiteId).catch(() => {});
    }

    const result: SiteInfoData = { ssl, geo, headers };
    this.cache.set(hostname, { data: result, exp: Date.now() + this.TTL });
    return result;
  }

  // ── SSL ──────────────────────────────────────────────────────────────────
  private checkSsl(hostname: string): Promise<SslInfo | null> {
    return new Promise(resolve => {
      try {
        const socket = tls.connect(
          { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
          () => {
            try {
              const cert = socket.getPeerCertificate(false);
              socket.end();
              if (!cert || !cert.subject) { resolve(null); return; }

              const validTo  = cert.valid_to  ? new Date(cert.valid_to)  : null;
              const validFrom= cert.valid_from ? new Date(cert.valid_from): null;
              const daysLeft = validTo ? Math.ceil((validTo.getTime() - Date.now()) / 86_400_000) : null;
              const toStr = (v: string | string[] | undefined): string | null =>
                v == null ? null : Array.isArray(v) ? v[0] : v;
              const issuerCN  = toStr(cert.issuer?.CN)  ?? toStr(cert.issuer?.O)  ?? null;
              const subjectCN = toStr(cert.subject?.CN) ?? toStr(cert.subject?.O) ?? null;
              const selfSigned = cert.issuer?.CN === cert.subject?.CN;

              resolve({
                valid:      (daysLeft ?? 0) > 0,
                issuer:     issuerCN,
                subject:    subjectCN,
                validFrom:  validFrom?.toISOString().split('T')[0] ?? null,
                validTo:    validTo?.toISOString().split('T')[0]   ?? null,
                daysLeft,
                selfSigned,
              });
            } catch { socket.end(); resolve(null); }
          },
        );
        socket.on('error', () => resolve(null));
        socket.setTimeout(8_000, () => { socket.destroy(); resolve(null); });
      } catch { resolve(null); }
    });
  }

  // ── SECURITY HEADERS ─────────────────────────────────────────────────────
  private async fetchHeaders(url: string): Promise<Record<string, string> | null> {
    try {
      const target = url.startsWith('http') ? url : `https://${url}`;
      const res = await axios.head(target, {
        timeout: 8_000,
        maxRedirects: 3,
        validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
      });
      return res.headers as Record<string, string>;
    } catch {
      try {
        const target = url.startsWith('http') ? url : `https://${url}`;
        const res = await axios.get(target, {
          timeout: 8_000, maxRedirects: 3,
          validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0' },
        });
        return res.headers as Record<string, string>;
      } catch { return null; }
    }
  }

  private analyzeHeaders(h: Record<string, string>): SecHeadersInfo {
    const lower: Record<string, string> = {};
    for (const k of Object.keys(h)) lower[k.toLowerCase()] = h[k];

    const present: string[] = [];
    const missing: string[] = [];
    let score = 0;

    for (const def of SEC_HEADERS) {
      if (lower[def.key]) { present.push(def.name); score += def.points; }
      else                  missing.push(def.name);
    }

    const grade =
      score >= 95 ? 'A+' :
      score >= 80 ? 'A'  :
      score >= 65 ? 'B'  :
      score >= 50 ? 'C'  :
      score >= 35 ? 'D'  : 'F';

    return {
      hsts:                !!lower['strict-transport-security'],
      csp:                 !!lower['content-security-policy'],
      xFrameOptions:       !!lower['x-frame-options'],
      xContentTypeOptions: !!lower['x-content-type-options'],
      xXssProtection:      !!lower['x-xss-protection'],
      referrerPolicy:      !!lower['referrer-policy'],
      permissionsPolicy:   !!lower['permissions-policy'],
      coopPolicy:          !!lower['cross-origin-opener-policy'],
      coepPolicy:          !!lower['cross-origin-embedder-policy'],
      corpPolicy:          !!lower['cross-origin-resource-policy'],
      score, grade, present, missing,
    };
  }

  // ── GEO IP ───────────────────────────────────────────────────────────────
  private async fetchGeo(hostname: string): Promise<GeoInfo | null> {
    try {
      const { data } = await axios.get(
        `http://ip-api.com/json/${hostname}?fields=status,country,countryCode,city,regionName,isp,org,timezone`,
        { timeout: 6_000 },
      );
      if (data.status !== 'success') return null;
      return {
        country:     data.country     ?? null,
        countryCode: data.countryCode ?? null,
        city:        data.city        ?? null,
        region:      data.regionName  ?? null,
        isp:         data.isp         ?? null,
        org:         data.org         ?? null,
        timezone:    data.timezone    ?? null,
      };
    } catch { return null; }
  }

  private extractHost(url: string): string {
    try {
      const u = url.startsWith('http') ? url : `https://${url}`;
      return new URL(u).hostname;
    } catch { return ''; }
  }
}
