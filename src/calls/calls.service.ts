import { Injectable, OnModuleInit, NotFoundException, ConflictException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export const ALLOWED_COLORS = ['normal', 'green'] as const;
export type CategoryColor = typeof ALLOWED_COLORS[number];

const DEFAULT_CATEGORIES: { name: string; color: CategoryColor }[] = [
  { name: '102 ga',          color: 'normal' },
  { name: 'Firibgarlik',     color: 'normal' },
  { name: 'Ijtimoiy tarmoq', color: 'normal' },
  { name: 'Telegram',        color: 'normal' },
  { name: 'CSEC',            color: 'green'  },
  { name: 'Boshqa',          color: 'normal' },
];

function assertColor(color: unknown): CategoryColor {
  if (!ALLOWED_COLORS.includes(color as CategoryColor)) {
    throw new BadRequestException(`Color noto'g'ri. Ruxsat etilgan: ${ALLOWED_COLORS.join(', ')}`);
  }
  return color as CategoryColor;
}

export interface CallFilter {
  month?: string;     // 'YYYY-MM'
  from?: string;      // 'YYYY-MM-DD'
  to?: string;        // 'YYYY-MM-DD'
  category?: string;
}

@Injectable()
export class CallsService implements OnModuleInit {
  constructor(private prisma: PrismaService) {}

  async onModuleInit() {
    await this.seedCategories();
  }

  private async seedCategories() {
    for (const { name, color } of DEFAULT_CATEGORIES) {
      // CSEC default rangini har boot'da reseed qilamiz, boshqalarini foydalanuvchi
      // o'zgartirgan bo'lishi mumkin — tegmaymiz.
      const update = name === 'CSEC' ? { color } : {};
      await this.prisma.callCategory.upsert({
        where:  { name },
        update,
        create: { name, color },
      });
    }
  }

  // ── Categories ──────────────────────────────
  listCategories() {
    return this.prisma.callCategory.findMany({ orderBy: { createdAt: 'asc' } });
  }

  async createCategory(name: string, color: string = 'normal') {
    const trimmed = (name ?? '').trim();
    if (!trimmed) throw new ConflictException('Kategoriya nomi bo\'sh');
    const safeColor = assertColor(color);
    try {
      return await this.prisma.callCategory.create({ data: { name: trimmed, color: safeColor } });
    } catch {
      throw new ConflictException('Bunday kategoriya allaqachon mavjud');
    }
  }

  async updateCategory(id: string, data: { name?: string; color?: string }) {
    const cat = await this.prisma.callCategory.findUnique({ where: { id } });
    if (!cat) throw new NotFoundException();

    const update: { name?: string; color?: string } = {};
    let renameFrom: string | null = null;
    let renameTo:   string | null = null;

    if (data.name !== undefined) {
      const trimmed = data.name.trim();
      if (!trimmed) throw new ConflictException('Kategoriya nomi bo\'sh');
      if (trimmed !== cat.name) {
        update.name = trimmed;
        renameFrom = cat.name;
        renameTo   = trimmed;
      }
    }
    if (data.color !== undefined) update.color = assertColor(data.color);

    try {
      if (renameFrom && renameTo) {
        const [updated] = await this.prisma.$transaction([
          this.prisma.callCategory.update({ where: { id }, data: update }),
          this.prisma.call.updateMany({ where: { category: renameFrom }, data: { category: renameTo } }),
        ]);
        return updated;
      }
      return await this.prisma.callCategory.update({ where: { id }, data: update });
    } catch {
      throw new ConflictException('Yangilab bo\'lmadi (nom band yoki xato)');
    }
  }

  async deleteCategory(id: string) {
    const cat = await this.prisma.callCategory.findUnique({ where: { id } });
    if (!cat) throw new NotFoundException();
    await this.prisma.callCategory.delete({ where: { id } });
    return { ok: true };
  }

  // ── Calls ──────────────────────────────────
  list(filter: CallFilter) {
    const where: any = {};
    if (filter.category) where.category = filter.category;

    const range = this.buildDateRange(filter);
    if (range) where.createdAt = range;

    return this.prisma.call.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });
  }

  private buildDateRange(f: CallFilter): { gte: Date; lt: Date } | null {
    if (f.month) {
      const m = f.month.match(/^(\d{4})-(\d{2})$/);
      if (!m) return null;
      const year = +m[1];
      const month = +m[2] - 1;
      const gte = new Date(year, month, 1);
      const lt = new Date(year, month + 1, 1);
      return { gte, lt };
    }
    if (f.from || f.to) {
      const gte = f.from ? new Date(f.from + 'T00:00:00') : new Date(0);
      const toDate = f.to ? new Date(f.to + 'T00:00:00') : new Date();
      const lt = new Date(toDate.getTime() + 86_400_000);
      return { gte, lt };
    }
    return null;
  }

  async create(category: string) {
    const name = (category ?? '').trim();
    if (!name) throw new ConflictException('Kategoriya kerak');
    return this.prisma.call.create({ data: { category: name } });
  }

  async update(id: string, data: { phoneNumber?: string | null; category?: string; note?: string | null; createdAt?: string }) {
    const exists = await this.prisma.call.findUnique({ where: { id } });
    if (!exists) throw new NotFoundException();

    let createdAt: Date | undefined;
    if (data.createdAt !== undefined) {
      const d = new Date(data.createdAt);
      if (isNaN(d.getTime())) throw new BadRequestException('createdAt noto\'g\'ri sana formati');
      createdAt = d;
    }

    return this.prisma.call.update({
      where: { id },
      data: {
        phoneNumber: data.phoneNumber === undefined ? undefined : (data.phoneNumber?.trim() || null),
        category:    data.category    === undefined ? undefined : data.category,
        note:        data.note        === undefined ? undefined : (data.note?.trim() || null),
        createdAt,
      },
    });
  }

  async delete(id: string) {
    const exists = await this.prisma.call.findUnique({ where: { id } });
    if (!exists) throw new NotFoundException();
    await this.prisma.call.delete({ where: { id } });
    return { ok: true };
  }
}
