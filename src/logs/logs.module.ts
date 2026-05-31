import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { LogsController } from './logs.controller';
import { LogsService } from './logs.service';
import { DatabaseDumpsService } from './database-dumps.service';

@Module({
  imports: [PrismaModule],
  controllers: [LogsController],
  providers: [LogsService, DatabaseDumpsService],
  exports: [LogsService],
})
export class LogsModule {}
