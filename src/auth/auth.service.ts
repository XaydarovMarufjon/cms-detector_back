// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'crypto';
import * as bcrypt from 'bcryptjs';
import { UsersService } from 'src/users/users.service';
import { LogsService } from '../logs/logs.service';

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8h, matches JWT expiresIn
const EXTENDED_TTL_MS = 10 * 24 * 60 * 60 * 1000; // 10d, for active dashboard/checker users

@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersService,
    private readonly jwt: JwtService,
    private readonly logs: LogsService,
  ) { }

  async login(
    username: string,
    password: string,
    ctx?: { ip?: string; userAgent?: string },
  ) {
    const user = await this.users.findByUsername(username);
    if (!user) {
      await this.logs.writeAudit({
        action: 'auth.login.fail',
        username,
        metadata: { reason: 'user_not_found' },
        ip: ctx?.ip,
        userAgent: ctx?.userAgent,
      });
      throw new UnauthorizedException('Login yoki parol noto\'g\'ri');
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      await this.logs.writeAudit({
        userId: user.id,
        username: user.username,
        action: 'auth.login.fail',
        metadata: { reason: 'bad_password' },
        ip: ctx?.ip,
        userAgent: ctx?.userAgent,
      });
      throw new UnauthorizedException('Login yoki parol noto\'g\'ri');
    }

    const jti = randomUUID();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

    await this.logs.createSession({
      userId: user.id,
      jti,
      ip: ctx?.ip,
      userAgent: ctx?.userAgent,
      expiresAt,
    });

    const payload = { sub: user.id, username: user.username, role: user.role, jti };

    await this.logs.writeAudit({
      userId: user.id,
      username: user.username,
      action: 'auth.login',
      ip: ctx?.ip,
      userAgent: ctx?.userAgent,
      metadata: { jti },
    });

    return {
      access_token: this.jwt.sign(payload),
      user: { id: user.id, username: user.username, role: user.role },
    };
  }

  async logout(jti: string, userId?: string, username?: string, ctx?: { ip?: string; userAgent?: string }) {
    if (jti) await this.logs.revokeByJti(jti);
    await this.logs.writeAudit({
      userId: userId ?? null,
      username: username ?? null,
      action: 'auth.logout',
      ip: ctx?.ip,
      userAgent: ctx?.userAgent,
      metadata: { jti },
    });
    return { ok: true };
  }

  async refresh(
    user: { id: string; username: string; role: string; jti: string },
    ctx?: { ip?: string; userAgent?: string },
  ) {
    const expiresAt = new Date(Date.now() + EXTENDED_TTL_MS);
    await this.logs.extendSession(user.jti, expiresAt);

    const payload = { sub: user.id, username: user.username, role: user.role, jti: user.jti };
    const access_token = this.jwt.sign(payload, { expiresIn: '10d' });

    await this.logs.writeAudit({
      userId: user.id,
      username: user.username,
      action: 'auth.refresh',
      ip: ctx?.ip,
      userAgent: ctx?.userAgent,
      metadata: { jti: user.jti, expiresAt },
    });

    return { access_token, expiresAt };
  }

  async validateToken(payload: any) {
    return this.users.findById(payload.sub);
  }
}
