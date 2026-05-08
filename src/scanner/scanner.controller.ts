// src/scanner/scanner.controller.ts
import {
  Controller, Get, Post, Delete, Patch,
  Param, Body, Query, HttpCode, UseGuards, Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { ScannerService } from './scanner.service';
import { SubdomainService } from './subdomain.service';
import { WhoisService } from './whois.service';
import { SiteInfoService } from './site-info.service';
import { NucleiService } from './nuclei.service';
import { ThreatIntelService } from './threat-intel.service';
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
  ) {}

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

  @Get('subdomains')
  discoverSubdomains(@Query('domain') domain: string) {
    return this.subdomains.discover(domain);
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