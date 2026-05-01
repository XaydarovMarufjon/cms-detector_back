// src/auth/auth.controller.ts
import { Controller, Post, Body, HttpCode } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  // POST /api/auth/login
  @Post('login')
  @HttpCode(200)
  login(@Body() body: { username: string; password: string }) {
    return this.auth.login(body.username, body.password);
  }
}
