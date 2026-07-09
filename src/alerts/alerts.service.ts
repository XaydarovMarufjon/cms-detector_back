import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

const MONTHS: Record<string, number> = {
  jan:0,feb:1,mar:2,apr:3,may:4,jun:5,
  jul:6,aug:7,sep:8,oct:9,nov:10,dec:11,
};

function parseWhoisDate(s: string): Date | null {
  const m = s.match(/^(\d{1,2})-([A-Za-z]{3})-(\d{4})$/);
  if (m) {
    const mon = MONTHS[m[2].toLowerCase()];
    if (mon === undefined) return null;
    return new Date(+m[3], mon, +m[1]);
  }
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function daysUntil(d: Date): number {
  return Math.ceil((d.getTime() - Date.now()) / 86_400_000);
}

function resolveType(days: number): string | null {
  if (days <= 10)  return 'expiry_urgent';
  if (days <= 20)  return 'expiry_critical';
  if (days <= 30)  return 'expiry_warning';
  return null;
}

function resolveLabel(days: number): string {
  if (days <= 0)  return 'Muddat tugagan!';
  if (days <= 10) return `Faqat ${days} kun qoldi — SHOSHILINCH!`;
  return `${days} kun qoldi`;
}

const FALSE_POSITIVE_TTL_MS = 24 * 60 * 60 * 1000;

@Injectable()
export class AlertsService {
  constructor(private prisma: PrismaService) {}

  // WHOIS domain expiry alert
  async checkExpiry(domain: string, expirationDateStr: string, websiteId?: string) {
    const dueDate = parseWhoisDate(expirationDateStr);
    if (!dueDate) return;
    const days = daysUntil(dueDate);
    const type = resolveType(days);
    if (!type) return;

    const message = `${domain} domenining yangilanish muddati: ${resolveLabel(days)} (${expirationDateStr})`;
    await this.upsertAlert({ domain, type, message, dueDate, websiteId });
  }

  // SSL certificate expiry alert
  async checkSslExpiry(domain: string, daysLeft: number, validTo: string, websiteId?: string) {
    const type = resolveType(daysLeft);
    if (!type) return;

    const sslType = `ssl_${type}`;  // ssl_expiry_urgent, ssl_expiry_critical, ...
    const message = `${domain} SSL sertifikati: ${resolveLabel(daysLeft)} (${validTo})`;
    const dueDate = new Date(validTo);
    if (isNaN(dueDate.getTime())) return;

    await this.upsertAlert({ domain, type: sslType, message, dueDate, websiteId });
  }

  // CMS change detection alert
  async checkCmsChange(domain: string, oldCms: string, newCms: string, websiteId?: string) {
    const message = `${domain}: CMS o'zgardi — ${oldCms} → ${newCms}`;
    const dueDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await this.upsertAlert({ domain, type: 'cms_change', message, dueDate, websiteId });
  }

  // Site down alert
  async checkSiteDown(domain: string, httpStatus: number | null, websiteId?: string) {
    const isDown = httpStatus === null || httpStatus >= 500;
    if (!isDown) return;
    const status = httpStatus === null ? 'timeout/xatolik' : `HTTP ${httpStatus}`;
    const message = `${domain}: Sayt ishlamayapti (${status})`;
    const dueDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await this.upsertAlert({ domain, type: 'site_down', message, dueDate, websiteId });
  }

  // Defacement / content integrity alert
  async checkDefacementChange(domain: string, score: number, reasons: string[], websiteId?: string) {
    const detail = reasons.slice(0, 4).join(', ') || 'kontent fingerprint o\'zgardi';
    const message = `${domain}: Defacement gumoni — score ${score}/100 (${detail})`;
    const dueDate = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);
    await this.upsertAlert({ domain, type: 'defacement_change', message, dueDate, websiteId });
  }

  private async upsertAlert(data: {
    domain: string; type: string; message: string;
    dueDate: Date; websiteId?: string;
  }) {
    await this.deleteExpiredFalsePositives();

    const where = { domain_type: { domain: data.domain, type: data.type } };
    const existing = await this.prisma.alert.findUnique({ where });

    if (existing) {
      if (existing.falsePositive) return;

      await this.prisma.alert.update({
        where,
        data: {
          message: data.message,
          dueDate: data.dueDate,
          dismissed: false,
          websiteId: data.websiteId ?? null,
        },
      });
      return;
    }

    await this.prisma.alert.create({
      data: {
        domain: data.domain,
        type: data.type,
        message: data.message,
        dueDate: data.dueDate,
        dismissed: false,
        falsePositive: false,
        falsePositiveUntil: null,
        websiteId: data.websiteId ?? null,
      },
    });
  }

  async getAll() {
    await this.deleteExpiredFalsePositives();
    return this.prisma.alert.findMany({
      where:   { dismissed: false, falsePositive: false },
      orderBy: { dueDate: 'asc' },
    });
  }

  async getCount() {
    await this.deleteExpiredFalsePositives();
    return this.prisma.alert.count({ where: { dismissed: false, falsePositive: false } });
  }

  async getFalsePositive() {
    await this.deleteExpiredFalsePositives();
    return this.prisma.alert.findMany({
      where:   { falsePositive: true },
      orderBy: { dueDate: 'desc' },
    });
  }

  async dismiss(id: string) {
    return this.prisma.alert.update({
      where: { id },
      data:  { dismissed: true },
    });
  }

  async markFalsePositive(id: string) {
    return this.prisma.alert.update({
      where: { id },
      data:  {
        dismissed: true,
        falsePositive: true,
        falsePositiveUntil: this.falsePositiveUntil(),
      },
    });
  }

  async restore(id: string) {
    return this.prisma.alert.update({
      where: { id },
      data:  { dismissed: false, falsePositive: false, falsePositiveUntil: null },
    });
  }

  private falsePositiveUntil(): Date {
    return new Date(Date.now() + FALSE_POSITIVE_TTL_MS);
  }

  private async deleteExpiredFalsePositives() {
    await this.prisma.alert.deleteMany({
      where: {
        falsePositive: true,
        falsePositiveUntil: { lte: new Date() },
      },
    });
  }
}
