import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

const DAY_MS = 24 * 60 * 60 * 1000;
const DANGEROUS_PORTS = [21, 22, 23, 445, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5601, 5900, 6379, 9200, 9300, 27017];
const SERVICE_NAMES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  445: 'SMB',
  1433: 'MSSQL',
  1521: 'Oracle DB',
  2049: 'NFS',
  2375: 'Docker API',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5601: 'Kibana',
  5900: 'VNC',
  6379: 'Redis',
  9200: 'Elasticsearch',
  9300: 'Elasticsearch Node',
  27017: 'MongoDB',
};

@Injectable()
export class OverviewStatsService {
  constructor(private readonly prisma: PrismaService) {}

  async getStats() {
    const now = new Date();
    const since24h = new Date(now.getTime() - DAY_MS);
    const since14d = new Date(now.getTime() - 14 * DAY_MS);
    const staleCutoff = new Date(now.getTime() - 6 * 60 * 60 * 1000);

    const [
      websites,
      latestRows,
      scans14d,
      cves14d,
      autoScan,
      bulkJob,
      cveBySeverity,
      cveByStatus,
      cveByWebsite,
      subdomainByDomain,
      subdomainByWebsite,
      openPortsByPort,
      riskyPortsByWebsite,
      tasksByAssignee,
      alerts,
      scanResultsTotal,
      scanResults24h,
      scanErrors24h,
      nucleiTotal,
      subdomainTotal,
      openPortTotal,
      riskyOpenPortTotal,
      openTasks,
      inProgressTasks,
      criticalTasks,
      overdueTasks,
      unassignedTasks,
      cmsChanges24h,
      defacementSnapshots,
    ] = await Promise.all([
      this.prisma.website.findMany({
        select: {
          id: true,
          url: true,
          label: true,
          createdAt: true,
          cveScannedAt: true,
          subdomainsScannedAt: true,
        },
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.scanResult.findMany({
        distinct: ['websiteId'],
        orderBy: { scannedAt: 'desc' },
        select: {
          websiteId: true,
          cms: true,
          category: true,
          confidence: true,
          httpStatus: true,
          scannedAt: true,
          errorMessage: true,
        },
      }),
      this.prisma.scanResult.findMany({
        where: { scannedAt: { gte: since14d } },
        select: { scannedAt: true, errorMessage: true },
      }),
      this.prisma.nucleiResult.findMany({
        where: { scannedAt: { gte: since14d } },
        select: { scannedAt: true },
      }),
      this.prisma.autoScanState.findUnique({ where: { key: 'cms-auto-scan' } }),
      this.prisma.bulkScanJob.findFirst({
        where: { status: { in: ['PENDING', 'RUNNING'] } },
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          status: true,
          mode: true,
          total: true,
          completed: true,
          failed: true,
          skipped: true,
          running: true,
          pending: true,
          startedAt: true,
          updatedAt: true,
        },
      }),
      this.prisma.nucleiResult.groupBy({ by: ['severity'], _count: { _all: true } }),
      this.prisma.nucleiResult.groupBy({ by: ['status'], _count: { _all: true } }),
      this.prisma.nucleiResult.groupBy({ by: ['websiteId'], _count: { _all: true } }),
      this.prisma.subdomainCache.groupBy({ by: ['domain'], _count: { _all: true } }),
      this.prisma.subdomainCache.groupBy({ by: ['websiteId'], _count: { _all: true } }),
      this.prisma.portScanResult.groupBy({
        by: ['port'],
        where: { status: 'OPEN' },
        _count: { _all: true },
      }),
      this.prisma.portScanResult.groupBy({
        by: ['websiteId'],
        where: { status: 'OPEN', port: { in: DANGEROUS_PORTS } },
        _count: { _all: true },
      }),
      this.prisma.securityTask.groupBy({
        by: ['assigneeId'],
        where: { status: { in: ['OPEN', 'IN_PROGRESS'] } },
        _count: { _all: true },
      }),
      this.prisma.alert.findMany({
        where: { dismissed: false },
        select: { type: true, createdAt: true },
      }),
      this.prisma.scanResult.count(),
      this.prisma.scanResult.count({ where: { scannedAt: { gte: since24h } } }),
      this.prisma.scanResult.count({ where: { scannedAt: { gte: since24h }, errorMessage: { not: null } } }),
      this.prisma.nucleiResult.count(),
      this.prisma.subdomainCache.count(),
      this.prisma.portScanResult.count({ where: { status: 'OPEN' } }),
      this.prisma.portScanResult.count({ where: { status: 'OPEN', port: { in: DANGEROUS_PORTS } } }),
      this.prisma.securityTask.count({ where: { status: 'OPEN' } }),
      this.prisma.securityTask.count({ where: { status: 'IN_PROGRESS' } }),
      this.prisma.securityTask.count({ where: { priority: 'CRITICAL', status: { in: ['OPEN', 'IN_PROGRESS'] } } }),
      this.prisma.securityTask.count({ where: { dueDate: { lt: now }, status: { in: ['OPEN', 'IN_PROGRESS'] } } }),
      this.prisma.securityTask.count({ where: { assigneeId: null, status: { in: ['OPEN', 'IN_PROGRESS'] } } }),
      this.prisma.alert.count({ where: { type: 'cms_change', createdAt: { gte: since24h } } }),
      this.prisma.defacementSnapshot.findMany({
        select: {
          websiteId: true,
          domain: true,
          url: true,
          title: true,
          status: true,
          changeScore: true,
          changeReasons: true,
          keywordHits: true,
          lastChangedAt: true,
          lastCheckedAt: true,
          website: { select: { url: true, label: true } },
        },
        orderBy: [{ lastChangedAt: 'desc' }, { lastCheckedAt: 'desc' }],
      }),
    ]);

    const latestByWebsite = new Map(latestRows.map(row => [row.websiteId, row]));
    const cveCountByWebsite = new Map(cveByWebsite.map(row => [row.websiteId, row._count._all]));
    const riskyPortCountByWebsite = new Map(riskyPortsByWebsite.map(row => [row.websiteId, row._count._all]));
    const defacementByWebsite = new Map(defacementSnapshots.map(row => [row.websiteId, row]));
    const subdomainCountByWebsite = new Map(
      subdomainByWebsite
        .filter(row => !!row.websiteId)
        .map(row => [row.websiteId!, row._count._all]),
    );
    const taskCountByAssignee = new Map(tasksByAssignee.map(row => [row.assigneeId || 'unassigned', row._count._all]));
    const users = taskCountByAssignee.size
      ? await this.prisma.user.findMany({
          where: { id: { in: [...taskCountByAssignee.keys()].filter(id => id !== 'unassigned') } },
          select: { id: true, username: true },
        })
      : [];
    const userName = new Map(users.map(user => [user.id, user.username]));

    const scannedSites = latestRows.length;
    const totalSites = websites.length;
    const detected = latestRows.filter(row => !!row.cms).length;
    const unknown = latestRows.filter(row => !row.cms && !row.errorMessage).length;
    const lowConfidence = latestRows.filter(row => !!row.cms && row.confidence > 0 && row.confidence < 50).length;
    const staleSites = latestRows.filter(row => row.scannedAt < staleCutoff).length;
    const latestScanAt = latestRows.reduce<Date | null>((latest, row) => {
      if (!latest || row.scannedAt > latest) return row.scannedAt;
      return latest;
    }, null);

    const cmsCounts = this.countBy(latestRows, row => row.cms || 'Unknown');
    const categoryCounts = this.countBy(latestRows, row => row.category || 'Unknown');
    const severityRows = this.normalizeBuckets(
      cveBySeverity.map(row => ({ label: row.severity || 'unknown', count: row._count._all })),
      ['critical', 'high', 'medium', 'low', 'info', 'unknown'],
    );
    const statusRows = this.normalizeBuckets(
      cveByStatus.map(row => ({ label: row.status || 'PENDING', count: row._count._all })),
      ['PENDING', 'CONFIRMED', 'FALSE_POSITIVE'],
    );
    const criticalHighCve = severityRows
      .filter(row => ['critical', 'high'].includes(row.label.toLowerCase()))
      .reduce((sum, row) => sum + row.count, 0);
    const alertUrgent = alerts.filter(alert => this.alertSeverity(alert.type) === 'urgent').length;
    const alertCritical = alerts.filter(alert => this.alertSeverity(alert.type) === 'critical').length;
    const alertWarning = alerts.filter(alert => this.alertSeverity(alert.type) === 'warning').length;
    const alertNotice = alerts.filter(alert => this.alertSeverity(alert.type) === 'notice').length;
    const defacementSuspected = defacementSnapshots.filter(row => row.status === 'SUSPECTED').length;
    const defacementChanged = defacementSnapshots.filter(row => row.status === 'CHANGED').length;
    const defacementStable = defacementSnapshots.filter(row => row.status === 'STABLE' || row.status === 'BASELINE').length;

    const topRiskSites = websites
      .map(site => {
        const latest = latestByWebsite.get(site.id);
        const cveCount = cveCountByWebsite.get(site.id) || 0;
        const riskyPorts = riskyPortCountByWebsite.get(site.id) || 0;
        const subdomains = subdomainCountByWebsite.get(site.id) || 0;
        const defacement = defacementByWebsite.get(site.id);
        const reasons: string[] = [];
        let score = 0;

        if (!latest) {
          score += 12;
          reasons.push('Scan qilinmagan');
        } else {
          if (latest.errorMessage) {
            score += 30;
            reasons.push('Scan xatosi');
          }
          if ((latest.httpStatus || 0) >= 500) {
            score += 25;
            reasons.push(`HTTP ${latest.httpStatus}`);
          } else if ((latest.httpStatus || 0) >= 400) {
            score += 15;
            reasons.push(`HTTP ${latest.httpStatus}`);
          }
          if (!latest.cms && !latest.errorMessage) {
            score += 10;
            reasons.push('CMS noma\'lum');
          }
          if (latest.cms && latest.confidence < 50) {
            score += 8;
            reasons.push('Past confidence');
          }
          if (latest.scannedAt < staleCutoff) {
            score += 6;
            reasons.push('Scan eskirgan');
          }
        }
        if (cveCount) {
          score += Math.min(45, cveCount * 16);
          reasons.push(`${cveCount} CVE`);
        }
        if (riskyPorts) {
          score += Math.min(35, riskyPorts * 12);
          reasons.push(`${riskyPorts} xavfli port`);
        }
        if (defacement?.status === 'SUSPECTED') {
          score += 50;
          reasons.push('Defacement gumoni');
        } else if (defacement?.status === 'CHANGED') {
          score += 18;
          reasons.push('Kontent o\'zgargan');
        }
        if (!site.cveScannedAt) {
          score += 6;
          reasons.push('CVE scan yoq');
        }
        if (!site.subdomainsScannedAt) {
          score += 4;
          reasons.push('Subdomain scan yoq');
        }

        return {
          websiteId: site.id,
          url: site.url,
          label: site.label,
          score: Math.min(100, score),
          reasons: reasons.slice(0, 4),
          cveCount,
          riskyPorts,
          subdomains,
          defacementStatus: defacement?.status || null,
          lastScanAt: latest?.scannedAt?.toISOString() || null,
        };
      })
      .sort((a, b) => b.score - a.score || a.url.localeCompare(b.url))
      .slice(0, 10);

    const riskScore = topRiskSites[0]?.score || 0;
    const mitre = this.buildMitreStats({
      scannedSites,
      detectedTech: detected,
      nucleiTotal,
      criticalHighCve,
      openPortTotal,
      riskyOpenPortTotal,
      defacementSuspected,
      defacementChanged,
      subdomainTotal,
    });
    const postureScore = this.calculateExecutivePosture({
      riskScore,
      coveragePct: this.percent(scannedSites, totalSites),
      criticalHighCve,
      alertUrgent,
      alertCritical,
      defacementSuspected,
      riskyOpenPortTotal,
      overdueTasks,
      unassignedTasks,
    });
    const executiveRecommendations = this.executiveRecommendations({
      coveragePct: this.percent(scannedSites, totalSites),
      criticalHighCve,
      alertUrgent,
      alertCritical,
      defacementSuspected,
      riskyOpenPortTotal,
      overdueTasks,
      unassignedTasks,
      staleSites,
    });

    return {
      generatedAt: now.toISOString(),
      scan: {
        totalSites,
        scannedSites,
        unscannedSites: Math.max(0, totalSites - scannedSites),
        coveragePct: this.percent(scannedSites, totalSites),
        scanResultsTotal,
        scans24h: scanResults24h,
        errors24h: scanErrors24h,
        staleSites,
        latestScanAt: latestScanAt?.toISOString() || null,
      },
      cms: {
        detected,
        unknown,
        lowConfidence,
        changed24h: cmsChanges24h,
        top: this.topRows(cmsCounts, totalSites, 7),
        categories: this.topRows(categoryCounts, totalSites, 7),
      },
      cve: {
        total: nucleiTotal,
        affectedSites: cveByWebsite.length,
        criticalHigh: criticalHighCve,
        bySeverity: severityRows,
        byStatus: statusRows,
      },
      defacement: {
        monitored: defacementSnapshots.length,
        stable: defacementStable,
        changed: defacementChanged,
        suspected: defacementSuspected,
        baselineMissing: Math.max(0, totalSites - defacementSnapshots.length),
        lastChangedAt: defacementSnapshots.find(row => row.lastChangedAt)?.lastChangedAt?.toISOString() || null,
        recent: defacementSnapshots
          .filter(row => row.status === 'SUSPECTED' || row.status === 'CHANGED')
          .slice(0, 8)
          .map(row => ({
            websiteId: row.websiteId,
            domain: row.domain,
            url: row.website?.url || row.url,
            label: row.website?.label || row.title,
            status: row.status,
            score: row.changeScore,
            reasons: row.changeReasons,
            keywordHits: row.keywordHits,
            lastChangedAt: row.lastChangedAt?.toISOString() || null,
            lastCheckedAt: row.lastCheckedAt.toISOString(),
          })),
      },
      subdomains: {
        aliveSaved: subdomainTotal,
        deadTracked: 0,
        totalTracked: subdomainTotal,
        domainsTracked: subdomainByDomain.length,
        topDomains: subdomainByDomain
          .map(row => ({ domain: row.domain, count: row._count._all }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 6),
        note: 'Olik subdomainlar hozir cache jadvalida saqlanmaydi; tiriklari saqlanadi.',
      },
      ports: {
        open: openPortTotal,
        riskyOpen: riskyOpenPortTotal,
        affectedSites: riskyPortsByWebsite.length,
        topOpenPorts: openPortsByPort
          .map(row => ({ port: row.port, service: SERVICE_NAMES[row.port] || 'TCP', count: row._count._all }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 8),
      },
      tasks: {
        open: openTasks,
        inProgress: inProgressTasks,
        critical: criticalTasks,
        overdue: overdueTasks,
        unassigned: unassignedTasks,
        byAssignee: [...taskCountByAssignee.entries()]
          .map(([id, count]) => ({ name: id === 'unassigned' ? 'Biriktirilmagan' : userName.get(id) || id, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 6),
      },
      alerts: {
        total: alerts.length,
        urgent: alertUrgent,
        critical: alertCritical,
        warning: alertWarning,
        notice: alertNotice,
      },
      mitre,
      executive: {
        postureScore,
        postureLabel: postureScore >= 85 ? 'Barqaror' : postureScore >= 70 ? 'Nazoratda' : postureScore >= 50 ? 'Xavfli' : 'Kritik',
        criticalOpen: alertUrgent + alertCritical + criticalTasks + criticalHighCve + defacementSuspected,
        highPrioritySites: topRiskSites.filter(site => site.score >= 45).length,
        scanCoveragePct: this.percent(scannedSites, totalSites),
        cveCriticalHigh: criticalHighCve,
        defacementSuspected,
        riskyOpenPorts: riskyOpenPortTotal,
        overdueTasks,
        recommendations: executiveRecommendations,
      },
      process: {
        autoScan: autoScan ? {
          intervalMinutes: autoScan.intervalMinutes,
          lastStartedAt: autoScan.lastStartedAt?.toISOString() || null,
          lastFinishedAt: autoScan.lastFinishedAt?.toISOString() || null,
          lastStatus: autoScan.lastStatus,
          scannedInLastWindow: autoScan.scannedInLastWindow,
          totalAtLastWindow: autoScan.totalAtLastWindow,
        } : null,
        bulkJob: bulkJob ? {
          id: bulkJob.id,
          status: bulkJob.status,
          mode: bulkJob.mode,
          total: bulkJob.total,
          done: bulkJob.completed + bulkJob.failed + bulkJob.skipped,
          running: bulkJob.running,
          pending: bulkJob.pending,
          progressPct: this.percent(bulkJob.completed + bulkJob.failed + bulkJob.skipped, bulkJob.total),
          startedAt: bulkJob.startedAt?.toISOString() || null,
          updatedAt: bulkJob.updatedAt.toISOString(),
        } : null,
      },
      trends: {
        scans: this.days(since14d, now, scans14d.map(row => row.scannedAt)),
        scanErrors: this.days(since14d, now, scans14d.filter(row => !!row.errorMessage).map(row => row.scannedAt)),
        cve: this.days(since14d, now, cves14d.map(row => row.scannedAt)),
        newSites: this.days(since14d, now, websites.map(row => row.createdAt).filter(date => date >= since14d)),
      },
      risk: {
        score: riskScore,
        label: riskScore >= 75 ? 'Kritik' : riskScore >= 45 ? 'Yuqori' : riskScore >= 20 ? 'O\'rta' : 'Past',
        topSites: topRiskSites,
      },
    };
  }

  private buildMitreStats(input: {
    scannedSites: number;
    detectedTech: number;
    nucleiTotal: number;
    criticalHighCve: number;
    openPortTotal: number;
    riskyOpenPortTotal: number;
    defacementSuspected: number;
    defacementChanged: number;
    subdomainTotal: number;
  }) {
    const techniques = [
      {
        tacticId: 'TA0043',
        tactic: 'Reconnaissance',
        techniqueId: 'T1592',
        technique: 'Gather Victim Host Information',
        count: input.detectedTech,
        severity: 'medium',
        sources: ['CMS fingerprint', 'server headers'],
      },
      {
        tacticId: 'TA0043',
        tactic: 'Reconnaissance',
        techniqueId: 'T1590',
        technique: 'Gather Victim Network Information',
        count: input.subdomainTotal,
        severity: input.subdomainTotal > 50 ? 'medium' : 'low',
        sources: ['Subdomain discovery'],
      },
      {
        tacticId: 'TA0007',
        tactic: 'Discovery',
        techniqueId: 'T1046',
        technique: 'Network Service Discovery',
        count: input.openPortTotal,
        severity: input.riskyOpenPortTotal ? 'high' : 'medium',
        sources: ['Open port scan'],
      },
      {
        tacticId: 'TA0001',
        tactic: 'Initial Access',
        techniqueId: 'T1133',
        technique: 'External Remote Services',
        count: input.riskyOpenPortTotal,
        severity: input.riskyOpenPortTotal ? 'high' : 'low',
        sources: ['Risky exposed ports'],
      },
      {
        tacticId: 'TA0001',
        tactic: 'Initial Access',
        techniqueId: 'T1190',
        technique: 'Exploit Public-Facing Application',
        count: input.nucleiTotal,
        severity: input.criticalHighCve ? 'critical' : 'high',
        sources: ['Nuclei CVE findings'],
      },
      {
        tacticId: 'TA0040',
        tactic: 'Impact',
        techniqueId: 'T1491.002',
        technique: 'External Defacement',
        count: input.defacementSuspected + input.defacementChanged,
        severity: input.defacementSuspected ? 'critical' : 'medium',
        sources: ['Defacement fingerprint'],
      },
    ].filter(row => row.count > 0);

    const byTacticMap = new Map<string, { tacticId: string; tactic: string; count: number }>();
    for (const row of techniques) {
      const key = row.tacticId;
      const current = byTacticMap.get(key) || { tacticId: row.tacticId, tactic: row.tactic, count: 0 };
      current.count += row.count;
      byTacticMap.set(key, current);
    }

    return {
      total: techniques.reduce((sum, row) => sum + row.count, 0),
      techniques: techniques.sort((a, b) => b.count - a.count),
      byTactic: [...byTacticMap.values()].sort((a, b) => b.count - a.count),
      monitoredSites: input.scannedSites,
    };
  }

  private calculateExecutivePosture(input: {
    riskScore: number;
    coveragePct: number;
    criticalHighCve: number;
    alertUrgent: number;
    alertCritical: number;
    defacementSuspected: number;
    riskyOpenPortTotal: number;
    overdueTasks: number;
    unassignedTasks: number;
  }): number {
    let penalty = 0;
    penalty += Math.round(input.riskScore * 0.34);
    penalty += Math.min(18, Math.round(Math.max(0, 100 - input.coveragePct) * 0.22));
    penalty += Math.min(18, input.criticalHighCve * 3);
    penalty += Math.min(18, input.alertUrgent * 5 + input.alertCritical * 3);
    penalty += Math.min(20, input.defacementSuspected * 10);
    penalty += Math.min(14, input.riskyOpenPortTotal * 2);
    penalty += Math.min(10, input.overdueTasks * 2 + input.unassignedTasks);
    return Math.max(0, Math.min(100, 100 - penalty));
  }

  private executiveRecommendations(input: {
    coveragePct: number;
    criticalHighCve: number;
    alertUrgent: number;
    alertCritical: number;
    defacementSuspected: number;
    riskyOpenPortTotal: number;
    overdueTasks: number;
    unassignedTasks: number;
    staleSites: number;
  }) {
    const rows: Array<{ severity: 'critical' | 'high' | 'medium' | 'low'; title: string; detail: string }> = [];
    if (input.defacementSuspected) {
      rows.push({ severity: 'critical', title: 'Defacement incident tekshirilsin', detail: `${input.defacementSuspected} ta sayt gumonli` });
    }
    if (input.criticalHighCve) {
      rows.push({ severity: 'critical', title: 'Critical/High CVE yopilsin', detail: `${input.criticalHighCve} ta yuqori xavfli topilma` });
    }
    if (input.alertUrgent || input.alertCritical) {
      rows.push({ severity: 'high', title: 'Alertlar eskalatsiya qilinsin', detail: `${input.alertUrgent + input.alertCritical} ta muhim alert` });
    }
    if (input.riskyOpenPortTotal) {
      rows.push({ severity: 'high', title: 'Xavfli portlar cheklansin', detail: `${input.riskyOpenPortTotal} ta ochiq xavfli port` });
    }
    if (input.coveragePct < 90) {
      rows.push({ severity: 'medium', title: 'Scan qamrovi to\'ldirilsin', detail: `Hozirgi qamrov ${input.coveragePct}%` });
    }
    if (input.staleSites) {
      rows.push({ severity: 'medium', title: 'Eskirgan scanlar yangilansin', detail: `${input.staleSites} ta sayt 6 soatdan eski` });
    }
    if (input.overdueTasks || input.unassignedTasks) {
      rows.push({ severity: 'medium', title: 'Vazifa intizomi yaxshilansin', detail: `${input.overdueTasks} muddati o'tgan, ${input.unassignedTasks} biriktirilmagan` });
    }
    if (!rows.length) {
      rows.push({ severity: 'low', title: 'Monitoring holati barqaror', detail: 'Mavjud asosiy risklar nazoratda' });
    }
    return rows.slice(0, 6);
  }

  private countBy<T>(rows: T[], keyFn: (row: T) => string): Map<string, number> {
    const map = new Map<string, number>();
    for (const row of rows) {
      const key = keyFn(row);
      map.set(key, (map.get(key) || 0) + 1);
    }
    return map;
  }

  private topRows(counts: Map<string, number>, total: number, limit: number) {
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([label, count]) => ({ label, count, pct: this.percent(count, total || count) }));
  }

  private normalizeBuckets(rows: Array<{ label: string; count: number }>, labels: string[]) {
    const map = new Map(rows.map(row => [row.label, row.count]));
    const normalized = labels.map(label => ({ label, count: map.get(label) || 0 }));
    for (const row of rows) {
      if (!labels.includes(row.label)) normalized.push(row);
    }
    const total = normalized.reduce((sum, row) => sum + row.count, 0) || 1;
    return normalized.map(row => ({ ...row, pct: this.percent(row.count, total) }));
  }

  private days(from: Date, to: Date, dates: Date[]) {
    const buckets: Array<{ date: string; count: number }> = [];
    const cursor = new Date(from);
    cursor.setHours(0, 0, 0, 0);
    const end = new Date(to);
    end.setHours(0, 0, 0, 0);
    while (cursor <= end) {
      buckets.push({ date: cursor.toISOString().slice(0, 10), count: 0 });
      cursor.setDate(cursor.getDate() + 1);
    }
    const index = new Map(buckets.map((row, i) => [row.date, i]));
    for (const date of dates) {
      const key = date.toISOString().slice(0, 10);
      const idx = index.get(key);
      if (idx !== undefined) buckets[idx].count++;
    }
    return buckets;
  }

  private alertSeverity(type: string): 'urgent' | 'critical' | 'warning' | 'notice' {
    if (type.endsWith('urgent') || type === 'site_down' || type === 'defacement_change') return 'urgent';
    if (type.endsWith('critical')) return 'critical';
    if (type.endsWith('warning') || type === 'cms_change') return 'warning';
    return 'notice';
  }

  private percent(value: number, total: number) {
    if (!total || total <= 0) return 0;
    return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
  }
}
