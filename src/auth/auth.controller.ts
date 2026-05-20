// src/auth/auth.controller.ts
import { Controller, Post, Body, HttpCode, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { extractIp, extractUa } from '../logs/ua-parser';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  // POST /api/auth/login
  @Post('login')
  @HttpCode(200)
  login(@Body() body: { username: string; password: string }, @Req() req: Request) {
    return this.auth.login(body.username, body.password, {
      ip: extractIp(req),
      userAgent: extractUa(req),
    });
  }

  // POST /api/auth/logout — revokes current session
  @Post('logout')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  logout(@Req() req: Request) {
    const u = (req as any).user;
    return this.auth.logout(u?.jti, u?.id, u?.username, {
      ip: extractIp(req),
      userAgent: extractUa(req),
    });
  }

  // POST /api/auth/refresh — extends session TTL to 10d
  @Post('refresh')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  refresh(@Req() req: Request) {
    return this.auth.refresh((req as any).user, {
      ip: extractIp(req),
      userAgent: extractUa(req),
    });
  }
}
