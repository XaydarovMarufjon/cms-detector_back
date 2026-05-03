import { Controller, Get, Patch, Param, UseGuards } from '@nestjs/common';
import { AlertsService } from './alerts.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Public } from '../auth/decorators/public.decorator';

@Controller('alerts')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AlertsController {
  constructor(private readonly alerts: AlertsService) {}

  @Get()
  getAll() { return this.alerts.getAll(); }

  @Public()
  @Get('count')
  getCount() { return this.alerts.getCount().then(count => ({ count })); }

  @Patch(':id/dismiss')
  dismiss(@Param('id') id: string) { return this.alerts.dismiss(id); }
}
