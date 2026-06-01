import { Injectable } from '@nestjs/common';
import axios from 'axios';
import {
  arch,
  cpus,
  freemem,
  hostname,
  loadavg,
  networkInterfaces,
  platform,
  release,
  totalmem,
  uptime,
} from 'node:os';
import { readFileSync, statfsSync } from 'node:fs';
import { PrismaService } from '../prisma/prisma.service';

type PublicNetworkInfo = {
  ip: string | null;
  isp: string | null;
  country: string | null;
  city: string | null;
  error: string | null;
};

type SystemIssue = {
  source: 'api' | 'scan' | 'bulk' | 'feed' | 'database' | 'network';
  severity: 'warning' | 'error';
  message: string;
  detail: string | null;
  target: string | null;
  path: string | null;
  at: string | null;
};

type NetworkSnapshot = {
  rxBytes: number;
  txBytes: number;
  at: number;
};

@Injectable()
export class SystemStatusService {
  private publicNetworkCache: { value: PublicNetworkInfo; expiresAt: number } | null = null;
  private networkSnapshot: NetworkSnapshot | null = null;

  constructor(private readonly prisma: PrismaService) {}

  async getStatus() {
    const now = new Date();
    const since24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const [db, publicNetwork] = await Promise.all([
      this.getDatabaseSnapshot(now, since24h),
      this.getPublicNetwork(),
    ]);

    const resources = this.getResources();
    const host = {
      hostname: hostname(),
      platform: `${platform()} ${release()}`,
      arch: arch(),
      publicIp: publicNetwork.ip,
      isp: publicNetwork.isp,
      country: publicNetwork.country,
      city: publicNetwork.city,
      networkError: publicNetwork.error,
      localIps: this.getLocalIps(),
    };

    const issues = [...db.issues];
    if (publicNetwork.error) {
      issues.unshift({
        source: 'network',
        severity: 'warning',
        message: 'Public IP aniqlanmadi',
        detail: publicNetwork.error,
        target: null,
        path: null,
        at: now.toISOString(),
      });
    }

    const score = this.calculateScore(resources, db.health, issues.length);
    const status = score < 55 || !db.health.ok ? 'ERROR' : score < 80 || issues.length > 0 ? 'WARN' : 'OK';

    return {
      generatedAt: now.toISOString(),
      status,
      score,
      runtime: {
        nodeVersion: process.version,
        env: process.env['NODE_ENV'] || 'development',
        pid: process.pid,
        uptimeSec: Math.floor(process.uptime()),
        systemUptimeSec: Math.floor(uptime()),
        startedAt: new Date(Date.now() - process.uptime() * 1000).toISOString(),
      },
      host,
      resources,
      database: db.database,
      scans: db.scans,
      tokens: db.tokens,
      activity: db.activity,
      errors: {
        summary: db.errorSummary,
        recent: issues.slice(0, 12),
      },
    };
  }

  private getResources() {
    const cpuList = cpus();
    const oneMinuteLoad = loadavg()[0] || 0;
    const cpuCores = Math.max(1, cpuList.length || 1);
    const memoryTotal = totalmem();
    const memoryFree = freemem();
    const memoryUsed = Math.max(0, memoryTotal - memoryFree);
    const procMem = process.memoryUsage();
    const disk = this.getDiskUsage();
    const network = this.getNetworkUsage();

    return {
      cpu: {
        cores: cpuCores,
        model: cpuList[0]?.model || 'unknown',
        load1m: Number(oneMinuteLoad.toFixed(2)),
        load5m: Number((loadavg()[1] || 0).toFixed(2)),
        load15m: Number((loadavg()[2] || 0).toFixed(2)),
        loadPct: this.percent(oneMinuteLoad, cpuCores),
      },
      memory: {
        totalBytes: memoryTotal,
        usedBytes: memoryUsed,
        freeBytes: memoryFree,
        usedPct: this.percent(memoryUsed, memoryTotal),
        processRssBytes: procMem.rss,
        heapUsedBytes: procMem.heapUsed,
        heapTotalBytes: procMem.heapTotal,
      },
      disk,
      network,
    };
  }

  private getDiskUsage() {
    try {
      const stats = statfsSync(process.cwd());
      const totalBytes = Number(stats.blocks) * Number(stats.bsize);
      const freeBytes = Number(stats.bavail) * Number(stats.bsize);
      const usedBytes = Math.max(0, totalBytes - freeBytes);
      return {
        path: process.cwd(),
        totalBytes,
        usedBytes,
        freeBytes,
        usedPct: this.percent(usedBytes, totalBytes),
      };
    } catch (err: any) {
      return {
        path: process.cwd(),
        totalBytes: 0,
        usedBytes: 0,
        freeBytes: 0,
        usedPct: 0,
        error: err?.message || 'disk usage unavailable',
      };
    }
  }

  private getNetworkUsage() {
    const current = this.readNetworkBytes();
    const now = Date.now();
    const previous = this.networkSnapshot;
    let rxBytesPerSec = 0;
    let txBytesPerSec = 0;

    if (previous && now > previous.at) {
      const seconds = Math.max(1, (now - previous.at) / 1000);
      rxBytesPerSec = Math.max(0, Math.round((current.rxBytes - previous.rxBytes) / seconds));
      txBytesPerSec = Math.max(0, Math.round((current.txBytes - previous.txBytes) / seconds));
    }

    this.networkSnapshot = {
      rxBytes: current.rxBytes,
      txBytes: current.txBytes,
      at: now,
    };

    return {
      rxBytes: current.rxBytes,
      txBytes: current.txBytes,
      rxBytesPerSec,
      txBytesPerSec,
      interfaceCount: current.interfaceCount,
      sampledAt: new Date(now).toISOString(),
      error: current.error,
    };
  }

  private readNetworkBytes(): { rxBytes: number; txBytes: number; interfaceCount: number; error: string | null } {
    try {
      const lines = readFileSync('/proc/net/dev', 'utf8').split('\n').slice(2);
      let rxBytes = 0;
      let txBytes = 0;
      let interfaceCount = 0;

      for (const line of lines) {
        const [rawName, rawStats] = line.split(':');
        const name = rawName?.trim();
        if (!name || name === 'lo' || !rawStats) continue;

        const fields = rawStats.trim().split(/\s+/).map(value => Number(value));
        if (fields.length < 16 || fields.some(value => Number.isNaN(value))) continue;

        rxBytes += fields[0] || 0;
        txBytes += fields[8] || 0;
        interfaceCount++;
      }

      return { rxBytes, txBytes, interfaceCount, error: null };
    } catch (err: any) {
      return {
        rxBytes: 0,
        txBytes: 0,
        interfaceCount: 0,
        error: err?.message || 'network usage unavailable',
      };
    }
  }

  private async getDatabaseSnapshot(now: Date, since24h: Date) {
    const started = Date.now();
    const issues: SystemIssue[] = [];

    try {
      await this.prisma.$queryRaw`SELECT 1`;
      const latencyMs = Date.now() - started;

      const [
        websitesTotal,
        scanResultsTotal,
        scanResults24h,
        scanErrors24h,
        nucleiFindingsTotal,
        subdomainsTotal,
        openPorts,
        runningBulkJobs,
        failedBulkJobs24h,
        activeSessions,
        issuedTokens24h,
        revokedTokens24h,
        auditEvents24h,
        auditErrors24h,
        loginFailures24h,
        openTasks,
        autoScanState,
        latestAuditErrors,
        latestScanErrors,
        latestBulkErrors,
        feedErrors,
      ] = await Promise.all([
        this.prisma.website.count(),
        this.prisma.scanResult.count(),
        this.prisma.scanResult.count({ where: { scannedAt: { gte: since24h } } }),
        this.prisma.scanResult.count({ where: { scannedAt: { gte: since24h }, errorMessage: { not: null } } }),
        this.prisma.nucleiResult.count(),
        this.prisma.subdomainCache.count(),
        this.prisma.portScanResult.count({ where: { status: 'OPEN' } }),
        this.prisma.bulkScanJob.count({ where: { status: { in: ['PENDING', 'RUNNING'] } } }),
        this.prisma.bulkScanJob.count({ where: { createdAt: { gte: since24h }, status: 'FAILED' } }),
        this.prisma.session.count({ where: { revokedAt: null, expiresAt: { gt: now } } }),
        this.prisma.session.count({ where: { createdAt: { gte: since24h } } }),
        this.prisma.session.count({ where: { revokedAt: { gte: since24h } } }),
        this.prisma.auditLog.count({ where: { createdAt: { gte: since24h } } }),
        this.prisma.auditLog.count({ where: { createdAt: { gte: since24h }, action: { contains: 'error' } } }),
        this.prisma.auditLog.count({ where: { createdAt: { gte: since24h }, action: 'auth.login.fail' } }),
        this.prisma.securityTask.count({ where: { status: { notIn: ['DONE', 'CLOSED', 'RESOLVED'] } } }),
        this.prisma.autoScanState.findUnique({ where: { key: 'cms-auto-scan' } }),
        this.prisma.auditLog.findMany({
          where: { action: { contains: 'error' } },
          orderBy: { createdAt: 'desc' },
          take: 4,
          select: { action: true, method: true, path: true, username: true, metadata: true, createdAt: true },
        }),
        this.prisma.scanResult.findMany({
          where: { errorMessage: { not: null } },
          orderBy: { scannedAt: 'desc' },
          take: 4,
          select: {
            errorMessage: true,
            scannedAt: true,
            httpStatus: true,
            website: { select: { url: true, label: true } },
          },
        }),
        this.prisma.bulkScanJob.findMany({
          where: { status: 'FAILED' },
          orderBy: { updatedAt: 'desc' },
          take: 3,
          select: { id: true, errorMessage: true, updatedAt: true },
        }),
        this.prisma.threatFeed.findMany({
          where: { OR: [{ lastStatus: 'error' }, { lastError: { not: null } }] },
          orderBy: { updatedAt: 'desc' },
          take: 3,
          select: { name: true, type: true, lastError: true, updatedAt: true },
        }),
      ]);

      issues.push(
        ...latestAuditErrors.map(log => ({
          source: 'api' as const,
          severity: 'error' as const,
          message: `${log.method || 'API'} ${log.path || log.action}`,
          detail: this.metadataStatus(log.metadata),
          target: log.username,
          path: log.path,
          at: log.createdAt.toISOString(),
        })),
        ...latestScanErrors.map(row => ({
          source: 'scan' as const,
          severity: 'warning' as const,
          message: row.website?.label || row.website?.url || 'Scan xatosi',
          detail: row.errorMessage || (row.httpStatus ? `HTTP ${row.httpStatus}` : null),
          target: row.website?.url || null,
          path: null,
          at: row.scannedAt.toISOString(),
        })),
        ...latestBulkErrors.map(job => ({
          source: 'bulk' as const,
          severity: 'error' as const,
          message: `Bulk scan xato: ${job.id.slice(0, 8)}`,
          detail: job.errorMessage,
          target: job.id,
          path: null,
          at: job.updatedAt.toISOString(),
        })),
        ...feedErrors.map(feed => ({
          source: 'feed' as const,
          severity: 'warning' as const,
          message: `${feed.name} (${feed.type})`,
          detail: feed.lastError,
          target: feed.name,
          path: null,
          at: feed.updatedAt.toISOString(),
        })),
      );

      issues.sort((a, b) => new Date(b.at || 0).getTime() - new Date(a.at || 0).getTime());

      return {
        health: { ok: true, latencyMs },
        database: {
          ok: true,
          latencyMs,
          provider: 'postgresql',
          websitesTotal,
          scanResultsTotal,
        },
        scans: {
          websitesTotal,
          scanResultsTotal,
          scanResults24h,
          scanErrors24h,
          nucleiFindingsTotal,
          subdomainsTotal,
          openPorts,
          runningBulkJobs,
          failedBulkJobs24h,
          openTasks,
          autoScan: autoScanState
            ? {
                intervalMinutes: autoScanState.intervalMinutes,
                lastStartedAt: autoScanState.lastStartedAt?.toISOString() || null,
                lastFinishedAt: autoScanState.lastFinishedAt?.toISOString() || null,
                lastStatus: autoScanState.lastStatus,
                lastError: autoScanState.lastError,
                scannedInLastWindow: autoScanState.scannedInLastWindow,
                totalAtLastWindow: autoScanState.totalAtLastWindow,
              }
            : null,
        },
        tokens: {
          activeSessions,
          issued24h: issuedTokens24h,
          revoked24h: revokedTokens24h,
          trackedAiTokens24h: null,
          trackingNote: 'JWT sessiyalari kuzatiladi; AI/LLM token sarfi bu loyihada hali log qilinmaydi.',
        },
        activity: {
          writeEvents24h: auditEvents24h,
          apiErrors24h: auditErrors24h,
          loginFailures24h,
        },
        errorSummary: {
          apiErrors24h: auditErrors24h,
          scanErrors24h,
          failedBulkJobs24h,
          feedErrors: feedErrors.length,
          loginFailures24h,
        },
        issues,
      };
    } catch (err: any) {
      const message = err?.message || 'Database status unavailable';
      return {
        health: { ok: false, latencyMs: Date.now() - started, error: message },
        database: {
          ok: false,
          latencyMs: Date.now() - started,
          provider: 'postgresql',
          error: message,
          websitesTotal: 0,
          scanResultsTotal: 0,
        },
        scans: {
          websitesTotal: 0,
          scanResultsTotal: 0,
          scanResults24h: 0,
          scanErrors24h: 0,
          nucleiFindingsTotal: 0,
          subdomainsTotal: 0,
          openPorts: 0,
          runningBulkJobs: 0,
          failedBulkJobs24h: 0,
          openTasks: 0,
          autoScan: null,
        },
        tokens: {
          activeSessions: 0,
          issued24h: 0,
          revoked24h: 0,
          trackedAiTokens24h: null,
          trackingNote: 'DB ulanmagani uchun token statistikasi olinmadi.',
        },
        activity: {
          writeEvents24h: 0,
          apiErrors24h: 0,
          loginFailures24h: 0,
        },
        errorSummary: {
          apiErrors24h: 0,
          scanErrors24h: 0,
          failedBulkJobs24h: 0,
          feedErrors: 0,
          loginFailures24h: 0,
        },
        issues: [{
          source: 'database' as const,
          severity: 'error' as const,
          message: 'Database ulanmagan',
          detail: message,
          target: null,
          path: null,
          at: now.toISOString(),
        }],
      };
    }
  }

  private async getPublicNetwork(): Promise<PublicNetworkInfo> {
    const now = Date.now();
    if (this.publicNetworkCache && this.publicNetworkCache.expiresAt > now) {
      return this.publicNetworkCache.value;
    }

    try {
      const res = await axios.get<any>('https://ipwho.is/', { timeout: 3500 });
      if (res.data?.success === false) throw new Error(res.data?.message || 'ipwho.is failed');
      const value = {
        ip: res.data?.ip || null,
        isp: res.data?.connection?.isp || res.data?.connection?.org || null,
        country: res.data?.country || null,
        city: res.data?.city || null,
        error: null,
      };
      this.publicNetworkCache = { value, expiresAt: now + 60 * 60 * 1000 };
      return value;
    } catch (err: any) {
      const value = {
        ip: null,
        isp: null,
        country: null,
        city: null,
        error: err?.message || 'public ip lookup failed',
      };
      this.publicNetworkCache = { value, expiresAt: now + 5 * 60 * 1000 };
      return value;
    }
  }

  private getLocalIps() {
    const ips: string[] = [];
    for (const entries of Object.values(networkInterfaces())) {
      for (const item of entries || []) {
        if (!item.internal && item.address) ips.push(item.address);
      }
    }
    return [...new Set(ips)];
  }

  private metadataStatus(metadata: unknown): string | null {
    if (!metadata || typeof metadata !== 'object') return null;
    const status = (metadata as any).status;
    const durationMs = (metadata as any).durationMs;
    const bits: string[] = [];
    if (status) bits.push(`status: ${status}`);
    if (durationMs !== undefined) bits.push(`${durationMs}ms`);
    return bits.length ? bits.join(' · ') : null;
  }

  private calculateScore(resources: ReturnType<SystemStatusService['getResources']>, db: { ok: boolean }, issueCount: number) {
    let score = 100;
    if (!db.ok) score -= 35;
    if (resources.cpu.loadPct > 95) score -= 25;
    else if (resources.cpu.loadPct > 75) score -= 12;
    if (resources.memory.usedPct > 92) score -= 25;
    else if (resources.memory.usedPct > 82) score -= 12;
    if (resources.disk.usedPct > 92) score -= 18;
    else if (resources.disk.usedPct > 85) score -= 8;
    score -= Math.min(20, issueCount * 3);
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  private percent(value: number, total: number) {
    if (!total || total <= 0) return 0;
    return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
  }
}
