import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { VulnerabilitiesController } from './vulnerabilities.controller';
import { VulnerabilitiesService } from './vulnerabilities.service';

@Module({
  imports: [PrismaModule],
  controllers: [VulnerabilitiesController],
  providers: [VulnerabilitiesService],
})
export class VulnerabilitiesModule {}
