// src/auth/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { LogsService } from '../logs/logs.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly logs: LogsService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'cms-secret-key-2026',
    });
  }

  async validate(payload: any) {
    // Backward compat: tokens issued before session tracking lack jti.
    // Reject them so users re-login and get a tracked session.
    if (!payload?.jti) throw new UnauthorizedException('Session yo\'q, qayta kiring');

    const session = await this.logs.findSessionByJti(payload.jti);
    if (!session)            throw new UnauthorizedException('Session topilmadi');
    if (session.revokedAt)   throw new UnauthorizedException('Session bekor qilingan');
    if (session.expiresAt && session.expiresAt < new Date()) {
      throw new UnauthorizedException('Session muddati tugagan');
    }

    return {
      id: payload.sub,
      username: payload.username,
      role: payload.role,
      jti: payload.jti,
      sessionId: session.id,
    };
  }
}
