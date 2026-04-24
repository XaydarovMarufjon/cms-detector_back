// src/scanner/scanner.service.ts — NestJS
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { CmsDetectorService } from './cms-detector.service';

@Injectable()
export class ScannerService {
  private readonly logger = new Logger(ScannerService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly detector: CmsDetectorService,
  ) { }

  @Cron(CronExpression.EVERY_DAY_AT_2AM)
  async scanAll() {
    const sites = await this.prisma.website.findMany();
    this.logger.log(`Scanning ${sites.length} sites...`);
    for (const site of sites) await this.scanOne(site.id, site.url);
  }

  async scanOne(websiteId: string, url: string) {
    try {
      const result = await this.detector.detect(url);
      return this.prisma.scanResult.create({
        data: {
          websiteId,
          cms: result.cms,
          version: result.version,
          category: result.category,
          confidence: result.confidence,
          detectionMethods: result.detectionMethod,
          serverTech: result.serverTech,
          jsFrameworks: result.jsFrameworks,
          rawSignals: result.rawSignals,
        },
      });
    }
    catch (err) {
      let message = 'Unknown error';

      if (err instanceof Error) {
        message = err.message;
      }

      return this.prisma.scanResult.create({
        data: {
          websiteId,
          errorMessage: message,
        },
      });
    }
  }

  async getLatestResults() {
    return this.prisma.scanResult.findMany({
      distinct: ['websiteId'],
      orderBy: { scannedAt: 'desc' },
      include: { website: true },
    });
  }
}