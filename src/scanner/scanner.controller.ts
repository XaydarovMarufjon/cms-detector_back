// src/scanner/scanner.controller.ts
import {
  Controller, Get, Post, Delete, Patch,
  Param, Body, Query, HttpCode, UseGuards, Res,
} from '@nestjs/common';
import type { Response } from 'express';
import axios from 'axios';
import { ScannerService } from './scanner.service';
import { SubdomainService } from './subdomain.service';
import { WhoisService } from './whois.service';
import { SiteInfoService } from './site-info.service';
import { NucleiService } from './nuclei.service';
import { ThreatIntelService } from './threat-intel.service';
import { CmsDetectorService } from './cms-detector.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { Public } from '../auth/decorators/public.decorator';

@Controller('scanner')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ScannerController {
  constructor(
    private readonly scanner:      ScannerService,
    private readonly subdomains:   SubdomainService,
    private readonly whois:        WhoisService,
    private readonly siteInfo:     SiteInfoService,
    private readonly prisma:       PrismaService,
    private readonly nuclei:       NucleiService,
    private readonly threatIntel:  ThreatIntelService,
    private readonly cmsDetector:  CmsDetectorService,
  ) {}

  @Get('proxies')
  getProxies() { return this.cmsDetector.getProxyStats(); }

  @Post('proxies/refresh')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  async refreshProxies() {
    await this.cmsDetector.refreshProxies();
    return this.cmsDetector.getProxyStats();
  }

  @Post('proxies/auto-refresh')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  setAutoRefresh(@Body() body: { enabled: boolean }) {
    this.cmsDetector.setAutoRefreshEnabled(!!body?.enabled);
    return this.cmsDetector.getProxyStats();
  }

  @Post('proxies/test')
  @HttpCode(200)
  async testProxy(@Body() body: { proxy?: string; index?: number }) {
    return this.cmsDetector.testProxy(body || {});
  }

  private static ispCache: { data: any; exp: number } | null = null;

  @Public()
  @Get('isp')
  async getIsp() {
    const now = Date.now();
    if (ScannerController.ispCache && ScannerController.ispCache.exp > now) {
      return ScannerController.ispCache.data;
    }
    const empty = { isp: null, ip: null, country: null, city: null };

    // ipwho.is — bepul, CORS, key kerak emas
    try {
      const r = await axios.get<any>('https://ipwho.is/', { timeout: 6000 });
      if (r.data?.success !== false) {
        const data = {
          isp:     r.data?.connection?.isp || r.data?.connection?.org || null,
          ip:      r.data?.ip      || null,
          country: r.data?.country || null,
          city:    r.data?.city    || null,
        };
        ScannerController.ispCache = { data, exp: now + 3_600_000 }; // 1h cache
        return data;
      }
    } catch { /* fallback */ }

    // Fallback: ip-api.com
    try {
      const r = await axios.get<any>('http://ip-api.com/json/', { timeout: 6000 });
      if (r.data?.status === 'success') {
        const data = {
          isp:     r.data?.isp     || r.data?.org || null,
          ip:      r.data?.query   || null,
          country: r.data?.country || null,
          city:    r.data?.city    || null,
        };
        ScannerController.ispCache = { data, exp: now + 3_600_000 };
        return data;
      }
    } catch { /* fallback */ }

    ScannerController.ispCache = { data: empty, exp: now + 300_000 }; // 5min cache for failure
    return empty;
  }

  // ── Hamma ko'ra oladi ────────────────────────────
  @Get('results')
  getResults() { return this.scanner.getLatestResults(); }

  @Get('export')
  async exportCsv(@Res() res: Response) {
    const csv = await this.scanner.exportCsv();
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="cms-scan-results.csv"');
    res.send(csv);
  }

  @Get('can-embed')
  canEmbed(@Query('url') url: string) { return this.scanner.checkCanEmbed(url); }

  @Public()
  @Get('whois')
  getWhois(@Query('domain') domain: string) { return this.whois.lookup(domain); }

  @Public()
  @Get('site-info')
  getSiteInfo(@Query('url') url: string, @Query('websiteId') websiteId?: string) {
    return this.siteInfo.analyze(url, websiteId);
  }

  @Get('subdomains/cache')
  getCachedSubdomains(@Query('domain') domain: string) {
    return this.subdomains.getCachedAlive(domain);
  }

  @Get('subdomains')
  discoverSubdomains(@Query('domain') domain: string, @Query('websiteId') websiteId?: string) {
    return this.subdomains.discover(domain, websiteId);
  }

  @Get('websites')
  getAllWebsites() {
    return this.prisma.website.findMany({ orderBy: { createdAt: 'desc' } });
  }

  // ── Interval sozlash ─────────────────────────────
  @Get('interval')
  getInterval() { return this.scanner.getInterval(); }

  @Post('interval')
  @Roles('ADMIN')
  setInterval(@Body() body: { minutes: number }) {
    return this.scanner.setInterval(body.minutes);
  }

  // ── ADMIN va WORKER ──────────────────────────────
  @Post('scan')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  scanOne(@Body() body: { websiteId: string; url: string }) {
    return this.scanner.scanOne(body.websiteId, body.url);
  }

  @Post('scan-all')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  scanAll() { return this.scanner.scanAll(); }

  @Post('websites')
  @Roles('ADMIN', 'WORKER')
  createWebsite(@Body() body: { url: string; label?: string }) {
    return this.prisma.website.create({ data: { url: body.url, label: body.label } });
  }

  @Patch('websites/:id')
  @Roles('ADMIN', 'WORKER')
  updateWebsite(@Param('id') id: string, @Body() body: { url?: string; label?: string }) {
    return this.prisma.website.update({ where: { id }, data: body });
  }

  // ── Nuclei CVE skan ──────────────────────────────
  @Get('nuclei-results')
  getAllNucleiResults() {
    return this.nuclei.getAllResults();
  }

  @Get('nuclei-monitoring')
  getMonitoringResults() {
    return this.nuclei.getMonitoringResults();
  }

  @Get('nuclei-rejected')
  getRejectedResults() {
    return this.nuclei.getRejectedResults();
  }

  @Patch('nuclei-result/:id/status')
  @Roles('ADMIN', 'WORKER')
  updateCveStatus(
    @Param('id') id: string,
    @Body() body: { status: 'PENDING' | 'FALSE_POSITIVE' | 'CONFIRMED' },
  ) {
    return this.nuclei.updateCveStatus(id, body.status);
  }

  @Get('nuclei-progress')
  getNucleiProgress() {
    return this.nuclei.getProgress();
  }

  @Get('nuclei-interval')
  getNucleiInterval() {
    return this.nuclei.getNucleiInterval();
  }

  @Post('nuclei-interval')
  @Roles('ADMIN')
  setNucleiInterval(@Body() body: { minutes: number }) {
    return this.nuclei.setNucleiInterval(body.minutes);
  }

  @Post('nuclei-all')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  runNucleiAll() {
    return this.nuclei.scanAllWebsites();
  }

  @Get('nuclei/:websiteId')
  getNucleiResults(@Param('websiteId') websiteId: string) {
    return this.nuclei.getResults(websiteId);
  }

  @Post('nuclei/:websiteId')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  runNucleiScan(
    @Param('websiteId') websiteId: string,
    @Body() body: { subdomains: string[] },
  ) {
    return this.nuclei.scan(websiteId, body.subdomains ?? []);
  }

  // ── Threat Intel Feeds ───────────────────────────────────────────────────
  @Get('threat-feeds')
  getFeeds() { return this.threatIntel.getFeeds(); }

  @Post('threat-feeds')
  @Roles('ADMIN', 'WORKER')
  upsertFeed(@Body() body: { id?: string; name: string; type: string; url?: string; apiKey?: string; enabled?: boolean }) {
    return this.threatIntel.upsertFeed(body);
  }

  @Patch('threat-feeds/:id/toggle')
  @Roles('ADMIN', 'WORKER')
  toggleFeed(@Param('id') id: string, @Body() body: { enabled: boolean }) {
    return this.threatIntel.toggleFeed(id, body.enabled);
  }

  @Patch('threat-feeds/:id/configure')
  @Roles('ADMIN', 'WORKER')
  configureFeed(
    @Param('id') id: string,
    @Body() body: { url?: string; apiKey?: string; name?: string },
  ) {
    return this.threatIntel.configureFeed(id, body);
  }

  @Delete('threat-feeds/:id')
  @Roles('ADMIN')
  deleteFeed(@Param('id') id: string) { return this.threatIntel.deleteFeed(id); }

  @Post('threat-feeds/:id/sync')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  syncFeed(@Param('id') id: string) { return this.threatIntel.syncFeed(id); }

  @Post('threat-feeds/sync-all')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  syncAllFeeds() { return this.threatIntel.syncAllFeeds(); }

  @Get('cve-enrichment/:cveId')
  getEnrichment(@Param('cveId') cveId: string) { return this.threatIntel.getEnrichment(cveId); }

  @Post('cve-enrich-all')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  enrichAll() { return this.threatIntel.enrichAllPending(); }

  // ── Faqat ADMIN ──────────────────────────────────
  @Delete('websites/:id')
  @Roles('ADMIN')
  async deleteWebsite(@Param('id') id: string) {
    await this.prisma.scanResult.deleteMany({ where: { websiteId: id } });
    return this.prisma.website.delete({ where: { id } });
  }
}
