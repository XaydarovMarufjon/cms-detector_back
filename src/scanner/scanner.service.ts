import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { CmsDetectorService } from './cms-detector.service';

@Injectable()
export class ScannerService {
  // Logger: console.log o'rniga ishlatiladi
  private readonly logger = new Logger(ScannerService.name);

  // DI: NestJS bu serviclarni avtomatik beradi
  constructor(
    private readonly prisma: PrismaService,
    private readonly detector: CmsDetectorService,
  ) { }

  // Har kuni soat 02:00 da ishga tushadi
  @Cron(CronExpression.EVERY_DAY_AT_2AM)
  async scanAll() {
    const sites = await this.prisma.website.findMany();
    this.logger.log(`Scanning ${sites.length} sites`);

    for (const site of sites) {
      await this.scanOne(site.id, site.url);
    }
  }

  // Bitta saytni skanerlash va natijani saqlash
  async scanOne(websiteId: string, url: string) {
    const result = await this.detector.detect(url);

    return this.prisma.scanResult.create({
      data: {
        websiteId,
        cms: result.cms,
        version: result.version,
        confidence: result.confidence,
        detectionMethods: result.detectionMethod,
      },
    });
  }

  // Dashboard uchun: har bir saytning oxirgi natijasi
  async getLatestResults() {
    return this.prisma.scanResult.findMany({
      distinct: ['websiteId'],
      orderBy: { scannedAt: 'desc' },
      include: { website: true },
    });
  }