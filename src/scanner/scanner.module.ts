import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from '../prisma/prisma.module';
import { ScannerController } from './scanner.controller';
import { ScannerService } from './scanner.service';
import { CmsDetectorService } from './cms-detector.service';
import { SubdomainService } from './subdomain.service';

@Module({
  imports: [
    PrismaModule,
    ScheduleModule.forRoot(),
  ],
  controllers: [ScannerController],
  providers: [ScannerService, CmsDetectorService, SubdomainService],
})
export class ScannerModule { }