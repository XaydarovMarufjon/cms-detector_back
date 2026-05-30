import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { deviceFromUa } from './ua-parser';

type AuditInput = {
  userId?: string | null;
  username?: string | null;
  action: string;
  method?: string | null;
  path?: string | null;
  targetId?: string | null;
  metadata?: any;
  ip?: string | null;
  userAgent?: string | null;
};

@Injectable()
export class LogsService {
  constructor(private readonly prisma: PrismaService) {}

  writeAudit(input: AuditInput) {
    return this.prisma.auditLog.create({
      data: {
        userId: input.userId ?? null,
        username: input.username ?? null,
        action: input.action,
        method: input.method ?? null,
        path: input.path ?? null,
        targetId: input.targetId ?? null,
        metadata: input.metadata ?? undefined,
        ip: input.ip ?? null,
        userAgent: input.userAgent ?? null,
        device: deviceFromUa(input.userAgent),
      },
    });
  }

  createSession(input: {
    userId: string;
    jti: string;
    ip?: string | null;
    userAgent?: string | null;
    expiresAt: Date;
  }) {
    return this.prisma.session.create({
      data: {
        userId: input.userId,
        jti: input.jti,
        ip: input.ip ?? null,
        userAgent: input.userAgent ?? null,
        device: deviceFromUa(input.userAgent),
        expiresAt: input.expiresAt,
      },
    });
  }

  findSessionByJti(jti: string) {
    return this.prisma.session.findUnique({ where: { jti } });
  }

  revokeByJti(jti: string) {
    return this.prisma.session.updateMany({
      where: { jti, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  extendSession(jti: string, expiresAt: Date) {
    return this.prisma.session.updateMany({
      where: { jti, revokedAt: null },
      data: { expiresAt, lastActiveAt: new Date() },
    });
  }

  async listActivity(filter: {
    from?: string;
    to?: string;
    userId?: string;
    action?: string;
    page?: number;
    limit?: number;
  }) {
    const page = Math.max(1, Number(filter.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(filter.limit) || 50));
    const where: any = {};

    if (filter.userId) where.userId = filter.userId;
    if (filter.action) where.action = { contains: filter.action, mode: 'insensitive' };
    if (filter.from || filter.to) {
      where.createdAt = {};
      if (filter.from) where.createdAt.gte = new Date(filter.from);
      if (filter.to) where.createdAt.lte = new Date(filter.to);
    }

    const [items, total] = await this.prisma.$transaction([
      this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return { items, total, page, limit };
  }

  listSessions() {
    return this.prisma.session.findMany({
      where: {
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      include: {
        user: { select: { id: true, username: true, role: true } },
      },
      orderBy: { lastActiveAt: 'desc' },
    });
  }

  revokeSession(id: string) {
    return this.prisma.session.update({
      where: { id },
      data: { revokedAt: new Date() },
    });
  }
}
