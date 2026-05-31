import { Controller, Delete, Get, Param, Post, Query, Res, StreamableFile, UseGuards } from '@nestjs/common';
import type { Response } from 'express';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { LogsService } from './logs.service';
import { DatabaseDumpsService } from './database-dumps.service';

@Controller('logs')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class LogsController {
  constructor(
    private readonly logs: LogsService,
    private readonly dumps: DatabaseDumpsService,
  ) {}

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

  @Get('dumps')
  getDumps() {
    return this.dumps.listDumps();
  }

  @Post('dumps')
  createDump(@CurrentUser() user: any) {
    return this.dumps.createDump('MANUAL', user);
  }

  @Get('dumps/:id/download')
  async downloadDump(
    @Param('id') id: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const file = await this.dumps.getDownload(id);
    res.setHeader('Content-Type', file.mime);
    res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
    return new StreamableFile(file.stream);
  }

  @Delete('dumps/:id')
  deleteDump(@Param('id') id: string) {
    return this.dumps.deleteDump(id);
  }
}
