import { Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { LogsService } from './logs.service';

@Controller('logs')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class LogsController {
  constructor(private readonly logs: LogsService) {}

  @Get('activity')
  getActivity(
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('userId') userId?: string,
    @Query('action') action?: string,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    return this.logs.listActivity({
      from,
      to,
      userId,
      action,
      page: page ? Number(page) : undefined,
      limit: limit ? Number(limit) : undefined,
    });
  }

  @Get('sessions')
  getSessions() {
    return this.logs.listSessions();
  }

  @Post('sessions/:id/revoke')
  async revokeSession(@Param('id') id: string) {
    await this.logs.revokeSession(id);
    return { ok: true };
  }
}
