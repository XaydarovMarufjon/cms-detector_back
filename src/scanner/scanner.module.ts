import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from '../prisma/prisma.module';
import { ScannerController } from './scanner.controller';
import { ScannerService } from './scanner.service';
import { CmsDetectorService } from './cms-detector.service';

@Module({
  imports: [
    PrismaModule,           // DB kerak
    ScheduleModule.forRoot(), // Cron kerak
  ],
  controllers: [ScannerController], // HTTP endpoint lar
  providers: [ScannerService, CmsDetectorService], // Logika
})
export class ScannerModule { }