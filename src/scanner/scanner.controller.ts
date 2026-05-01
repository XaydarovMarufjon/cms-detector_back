// src/scanner/scanner.controller.ts
import {
  Controller, Get, Post, Delete, Patch,
  Param, Body, HttpCode, UseGuards,
} from '@nestjs/common';
import { ScannerService } from './scanner.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@Controller('scanner')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ScannerController {
  constructor(
    private readonly scanner: ScannerService,
    private readonly prisma:  PrismaService,
  ) {}

  // ── Hamma ko'ra oladi ────────────────────────────
  @Get('results')
  getResults() { return this.scanner.getLatestResults(); }

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

  // ── Faqat ADMIN ──────────────────────────────────
  @Delete('websites/:id')
  @Roles('ADMIN')
  async deleteWebsite(@Param('id') id: string) {
    await this.prisma.scanResult.deleteMany({ where: { websiteId: id } });
    return this.prisma.website.delete({ where: { id } });
  }
}