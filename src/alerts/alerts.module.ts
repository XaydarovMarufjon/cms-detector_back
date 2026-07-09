import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from '../prisma/prisma.module';
import { AlertsController } from './alerts.controller';
import { AlertsService } from './alerts.service';
import { OsintDorkService } from './osint-dork.service';

@Module({
  imports: [PrismaModule, ScheduleModule.forRoot()],
  controllers: [AlertsController],
  providers: [AlertsService, OsintDorkService],
  exports: [AlertsService, OsintDorkService],
})
export class AlertsModule {}
