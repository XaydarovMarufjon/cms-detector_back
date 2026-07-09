import { Body, Controller, Get, Patch, Param, Post, UseGuards } from '@nestjs/common';
import { AlertsService } from './alerts.service';
import { OsintDorkService } from './osint-dork.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Public } from '../auth/decorators/public.decorator';

@Controller('alerts')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AlertsController {
  constructor(
    private readonly alerts: AlertsService,
    private readonly osintDork: OsintDorkService,
  ) {}

  @Get()
  getAll() { return this.alerts.getAll(); }

  @Get('false-positive')
  getFalsePositive() { return this.alerts.getFalsePositive(); }

  @Public()
  @Get('count')
  getCount() { return this.alerts.getCount().then(count => ({ count })); }

  @Get('osint/config')
  getOsintConfig() { return this.osintDork.getConfig(); }

  @Get('osint')
  getOsintFindings() { return this.osintDork.listActive(); }

  @Get('osint/false-positive')
  getOsintFalsePositive() { return this.osintDork.listFalsePositive(); }

  @Post('osint/scan')
  scanOsint(@Body() body: unknown) { return this.osintDork.scan(body as any); }

  @Post('osint/manual')
  createOsintManual(@Body() body: unknown) { return this.osintDork.createManual(body as any); }

  @Patch('osint/:id/dismiss')
  dismissOsint(@Param('id') id: string) { return this.osintDork.dismiss(id); }

  @Patch('osint/:id/false-positive')
  markOsintFalsePositive(@Param('id') id: string) { return this.osintDork.markFalsePositive(id); }

  @Patch('osint/:id/restore')
  restoreOsint(@Param('id') id: string) { return this.osintDork.restore(id); }

  @Patch(':id/dismiss')
  dismiss(@Param('id') id: string) { return this.alerts.dismiss(id); }

  @Patch(':id/false-positive')
  markFalsePositive(@Param('id') id: string) { return this.alerts.markFalsePositive(id); }

  @Patch(':id/restore')
  restore(@Param('id') id: string) { return this.alerts.restore(id); }
}
