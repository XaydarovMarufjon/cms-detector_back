import { Body, Controller, Get, HttpCode, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { VulnerabilitiesService } from './vulnerabilities.service';

@Controller('vulnerabilities')
@UseGuards(JwtAuthGuard, RolesGuard)
export class VulnerabilitiesController {
  constructor(private readonly vulnerabilities: VulnerabilitiesService) {}

  @Get('imports')
  imports() {
    return this.vulnerabilities.listImports();
  }

  @Get('export')
  exportAll() {
    return this.vulnerabilities.exportAll();
  }

  @Get('export/rows')
  exportRows() {
    return this.vulnerabilities.exportRows();
  }

  @Post('imports/sync')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  sync(@Body() body: unknown) {
    return this.vulnerabilities.replaceSnapshot(body);
  }
}
