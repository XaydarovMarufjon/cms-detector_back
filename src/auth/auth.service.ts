// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersService,
    private readonly jwt: JwtService,
  ) { }

  async login(username: string, password: string) {
    const user = await this.users.findByUsername(username);
    if (!user) throw new UnauthorizedException('Login yoki parol noto\'g\'ri');

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) throw new UnauthorizedException('Login yoki parol noto\'g\'ri');

    const payload = { sub: user.id, username: user.username, role: user.role };
    return {
      access_token: this.jwt.sign(payload),
      user: { id: user.id, username: user.username, role: user.role },
    };
  }

  async validateToken(payload: any) {
    return this.users.findById(payload.sub);
  }
}
