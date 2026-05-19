import {
  Controller, Get, Post, Patch, Delete,
  Body, Param, Query, UseGuards, HttpCode,
} from '@nestjs/common';
import { CallsService } from './calls.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@Controller()
@UseGuards(JwtAuthGuard, RolesGuard)
export class CallsController {
  constructor(private readonly calls: CallsService) {}

  // ── Categories ──────────────────────────────
  @Get('call-categories')
  listCategories() {
    return this.calls.listCategories();
  }

  @Post('call-categories')
  @Roles('ADMIN', 'WORKER')
  createCategory(@Body() body: { name: string; color?: string }) {
    return this.calls.createCategory(body.name, body.color);
  }

  @Patch('call-categories/:id')
  @Roles('ADMIN', 'WORKER')
  updateCategory(@Param('id') id: string, @Body() body: { name?: string; color?: string }) {
    return this.calls.updateCategory(id, body);
  }

  @Delete('call-categories/:id')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  deleteCategory(@Param('id') id: string) {
    return this.calls.deleteCategory(id);
  }

  // ── Calls ──────────────────────────────────
  @Get('calls')
  list(
    @Query('month') month?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('category') category?: string,
  ) {
    return this.calls.list({ month, from, to, category });
  }

  @Post('calls')
  @Roles('ADMIN', 'WORKER')
  create(@Body() body: { category: string }) {
    return this.calls.create(body.category);
  }

  @Patch('calls/:id')
  @Roles('ADMIN', 'WORKER')
  update(
    @Param('id') id: string,
    @Body() body: { phoneNumber?: string | null; category?: string; note?: string | null; createdAt?: string },
  ) {
    return this.calls.update(id, body);
  }

  @Delete('calls/:id')
  @Roles('ADMIN', 'WORKER')
  @HttpCode(200)
  delete(@Param('id') id: string) {
    return this.calls.delete(id);
  }
}
