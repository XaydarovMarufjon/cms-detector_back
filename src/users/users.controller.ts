// src/users/users.controller.ts
import {
  Controller, Get, Post, Patch, Delete,
  Body, Param, UseGuards, HttpCode,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
  constructor(private readonly users: UsersService) {}

  // Faqat ADMIN ko'ra oladi
  @Get()
  @Roles('ADMIN')
  findAll() {
    return this.users.findAll();
  }

  // Faqat ADMIN yarata oladi
  @Post()
  @Roles('ADMIN')
  create(@Body() body: { username: string; password: string; role: 'ADMIN' | 'WORKER' | 'MONITORING' }) {
    return this.users.create(body.username, body.password, body.role);
  }

  // Faqat ADMIN tahrirlaydi
  @Patch(':id')
  @Roles('ADMIN')
  update(@Param('id') id: string, @Body() body: { username?: string; password?: string; role?: string }) {
    return this.users.update(id, body);
  }

  // Faqat ADMIN o'chiradi
  @Delete(':id')
  @Roles('ADMIN')
  @HttpCode(200)
  delete(@Param('id') id: string) {
    return this.users.delete(id);
  }
}
