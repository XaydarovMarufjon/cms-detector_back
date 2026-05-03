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
  if (days <= 30)  return 'expiry_critical';
  if (days <= 60)  return 'expiry_warning';
  if (days <= 90)  return 'expiry_notice';
  return null;
}

function resolveLabel(days: number): string {
  if (days <= 0)  return 'Muddat tugagan!';
  if (days <= 10) return `Faqat ${days} kun qoldi — SHOSHILINCH!`;
  return `${days} kun qoldi`;
}

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

  private async upsertAlert(data: {
    domain: string; type: string; message: string;
    dueDate: Date; websiteId?: string;
  }) {
    await this.prisma.alert.upsert({
      where:  { domain_type: { domain: data.domain, type: data.type } },
      update: { message: data.message, dueDate: data.dueDate, dismissed: false, websiteId: data.websiteId ?? null },
      create: { domain: data.domain, type: data.type, message: data.message, dueDate: data.dueDate, dismissed: false, websiteId: data.websiteId ?? null },
    });
  }

  getAll() {
    return this.prisma.alert.findMany({
      where:   { dismissed: false },
      orderBy: { dueDate: 'asc' },
    });
  }

  getCount() {
    return this.prisma.alert.count({ where: { dismissed: false } });
  }

  async dismiss(id: string) {
    return this.prisma.alert.update({
      where: { id },
      data:  { dismissed: true },
    });
  }
}
