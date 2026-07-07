// src/auth/guards/jwt-auth.guard.ts
import { CanActivate, Injectable, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

const TOKENLESS_USER = {
  id: null,
  username: 'tokenless-admin',
  role: 'ADMIN',
  jti: null,
  sessionId: null,
};

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(ctx: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (isPublic) return true;

    const request = ctx.switchToHttp().getRequest<{ user?: any }>();
    request.user ??= TOKENLESS_USER;
    return true;
  }
}
