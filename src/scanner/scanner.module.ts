import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from '../prisma/prisma.module';
import { AlertsModule } from '../alerts/alerts.module';
import { ScannerController } from './scanner.controller';
import { ScannerService } from './scanner.service';
import { CmsDetectorService } from './cms-detector.service';
import { SubdomainService } from './subdomain.service';
import { WhoisService } from './whois.service';
import { SiteInfoService } from './site-info.service';
import { NucleiService } from './nuclei.service';
import { ThreatIntelService } from './threat-intel.service';
import { PortScannerService } from './port-scanner.service';
import { SystemStatusService } from './system-status.service';
import { OverviewStatsService } from './overview-stats.service';
import { CveCorrelationService } from './cve-correlation.service';

@Module({
  imports: [
    PrismaModule,
    ScheduleModule.forRoot(),
    AlertsModule,
  ],
  controllers: [ScannerController],
  providers: [ScannerService, CmsDetectorService, SubdomainService, WhoisService, SiteInfoService, NucleiService, ThreatIntelService, PortScannerService, SystemStatusService, OverviewStatsService, CveCorrelationService],
})
export class ScannerModule { }
