import {
  Controller, Get, Post, Param, Body, HttpCode, UseGuards,
} from '@nestjs/common';
import { ImageModerationService } from './image-moderation.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@Controller('image-moderation')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ImageModerationController {
  constructor(private readonly svc: ImageModerationService) {}

  @Get('status')
  status() { return this.svc.isRunning(); }

  @Get('overview')
  overview() { return this.svc.getOverview(); }

  @Get('site/:websiteId/scans')
  siteScans(@Param('websiteId') websiteId: string) {
    return this.svc.getSiteScans(websiteId);
  }

  @Get('scan/:scanId')
  scanDetail(@Param('scanId') scanId: string) {
    return this.svc.getScanDetail(scanId);
  }

  @Post('scan')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  scanOne(@Body() body: { websiteId: string; url: string }) {
    return this.svc.scanSite(body.websiteId, body.url);
  }

  @Post('scan-all')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  scanAll() { return this.svc.scanAll(); }
}
