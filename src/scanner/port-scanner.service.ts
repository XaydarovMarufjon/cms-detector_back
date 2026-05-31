import { BadRequestException, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { Socket } from 'net';
import pLimit from 'p-limit';
import { PrismaService } from '../prisma/prisma.service';

const DEFAULT_PORTS = [
  21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
  1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5601, 5900,
  6379, 8000, 8080, 8443, 9200, 9300, 27017,
];

const SERVICE_NAMES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  587: 'SMTP Submission',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle DB',
  2049: 'NFS',
  2375: 'Docker API',
  3000: 'Dev Server',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5601: 'Kibana',
  5900: 'VNC',
  6379: 'Redis',
  8000: 'HTTP Alt',
  8080: 'HTTP Proxy',
  8443: 'HTTPS Alt',
  9200: 'Elasticsearch',
  9300: 'Elasticsearch Node',
  27017: 'MongoDB',
};

type PortProbe = {
  host: string;
  port: number;
  status: 'OPEN' | 'CLOSED' | 'FILTERED';
  service: string | null;
  latencyMs: number | null;
  error: string | null;
};

@Injectable()
export class PortScannerService {
  constructor(private readonly prisma: PrismaService) {}

  async getLatest(websiteId: string) {
    const latest = await this.prisma.portScanResult.findFirst({
      where: { websiteId },
      orderBy: { scannedAt: 'desc' },
    });
    if (!latest) return [];

    return this.prisma.portScanResult.findMany({
      where: { websiteId, scanId: latest.scanId },
      orderBy: [{ status: 'asc' }, { port: 'asc' }],
    });
  }

  async scanWebsite(websiteId: string, input?: { host?: string; ports?: number[]; timeoutMs?: number }) {
    const website = await this.prisma.website.findUnique({ where: { id: websiteId } });
    if (!website) throw new BadRequestException('Website topilmadi');

    const websiteHost = this.hostname(website.url);
    const host = this.normalizeHost(input?.host || websiteHost);
    if (!host) throw new BadRequestException('Host topilmadi');

    const root = this.rootDomain(websiteHost);
    if (host !== websiteHost && host !== root && !host.endsWith(`.${root}`)) {
      throw new BadRequestException('Faqat shu sayt domeni yoki subdomenlarini skan qilish mumkin');
    }

    const ports = this.normalizePorts(input?.ports);
    const timeoutMs = Math.min(Math.max(input?.timeoutMs || 1800, 500), 5000);
    const scanId = randomUUID();
    const scannedAt = new Date();
    const limit = pLimit(40);

    const probes = await Promise.all(
      ports.map(port => limit(() => this.checkPort(host, port, timeoutMs))),
    );

    await this.prisma.portScanResult.createMany({
      data: probes.map(probe => ({
        websiteId,
        host: probe.host,
        port: probe.port,
        protocol: 'TCP',
        status: probe.status,
        service: probe.service,
        latencyMs: probe.latencyMs,
        error: probe.error,
        scanId,
        scannedAt,
      })),
    });

    return this.prisma.portScanResult.findMany({
      where: { scanId },
      orderBy: [{ status: 'asc' }, { port: 'asc' }],
    });
  }

  private checkPort(host: string, port: number, timeoutMs: number): Promise<PortProbe> {
    const started = Date.now();
    return new Promise(resolve => {
      const socket = new Socket();
      let done = false;

      const finish = (status: PortProbe['status'], error: string | null = null) => {
        if (done) return;
        done = true;
        socket.destroy();
        resolve({
          host,
          port,
          status,
          service: SERVICE_NAMES[port] ?? null,
          latencyMs: status === 'OPEN' ? Date.now() - started : null,
          error,
        });
      };

      socket.setTimeout(timeoutMs);
      socket.once('connect', () => finish('OPEN'));
      socket.once('timeout', () => finish('FILTERED', 'timeout'));
      socket.once('error', err => {
        const code = (err as NodeJS.ErrnoException).code || '';
        finish(code === 'ECONNREFUSED' ? 'CLOSED' : 'FILTERED', code || err.message);
      });
      socket.connect(port, host);
    });
  }

  private normalizePorts(ports?: number[]): number[] {
    const selected = ports?.length ? ports : DEFAULT_PORTS;
    const clean = [...new Set(selected.map(Number))]
      .filter(port => Number.isInteger(port) && port > 0 && port <= 65535)
      .sort((a, b) => a - b);
    if (!clean.length) throw new BadRequestException('Portlar noto\'g\'ri');
    if (clean.length > 100) throw new BadRequestException('Bir martada 100 tagacha port skan qiling');
    return clean;
  }

  private hostname(value: string): string {
    try {
      const url = value.startsWith('http') ? value : `https://${value}`;
      return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    } catch {
      return this.normalizeHost(value);
    }
  }

  private normalizeHost(value: string): string {
    return value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/^www\./, '');
  }

  private rootDomain(host: string): string {
    const parts = host.split('.').filter(Boolean);
    if (parts.length <= 2) return host;
    const lastTwo = parts.slice(-2).join('.');
    const lastThree = parts.slice(-3).join('.');
    return ['com.uz', 'gov.uz', 'edu.uz', 'org.uz', 'net.uz'].some(suffix => lastTwo === suffix)
      ? lastThree
      : lastTwo;
  }
}
