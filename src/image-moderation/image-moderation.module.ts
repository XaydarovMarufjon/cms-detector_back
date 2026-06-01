import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from '../prisma/prisma.module';
import { ImageModerationController } from './image-moderation.controller';
import { ImageModerationService } from './image-moderation.service';
import { ImageCrawlerService } from './image-crawler.service';
import { SightengineService } from './sightengine.service';

@Module({
  imports: [PrismaModule, ScheduleModule.forRoot()],
  controllers: [ImageModerationController],
  providers: [ImageModerationService, ImageCrawlerService, SightengineService],
})
export class ImageModerationModule {}
