import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { createReadStream } from 'fs';
import { createHash } from 'crypto';
import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import * as path from 'path';
import { CronJob } from 'cron';
import { PrismaService } from '../prisma/prisma.service';

type DumpTrigger = 'MANUAL' | 'AUTO';

interface DumpUser {
  id?: string | null;
  username?: string | null;
}

@Injectable()
export class DatabaseDumpsService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(DatabaseDumpsService.name);
  private readonly dumpDir = path.resolve(process.env.DB_DUMP_DIR || path.join(process.cwd(), 'storage', 'db-dumps'));
  private readonly retention = Math.max(1, Number(process.env.DB_DUMP_RETENTION || 30));
  private readonly cronExpr = process.env.DB_DUMP_CRON || '0 0 3 1 * *';
  private readonly scheduleLabel = process.env.DB_DUMP_SCHEDULE_LABEL || this.describeCron(this.cronExpr);
  private readonly autoEnabled = process.env.DB_DUMP_AUTO !== 'false';
  private readonly pgDumpBin = process.env.PG_DUMP_BIN || 'pg_dump';
  private job: CronJob | null = null;
  private running: Promise<unknown> | null = null;

  constructor(private readonly prisma: PrismaService) {}

  onModuleInit() {
    if (!this.autoEnabled) return;
    this.job = new CronJob(this.cronExpr, () => {
      this.createDump('AUTO').catch(err => {
        const message = err instanceof Error ? err.message : String(err);
        this.logger.error(`Auto database dump failed: ${message}`);
      });
    });
    this.job.start();
    this.logger.log(`Database dump auto schedule enabled: ${this.cronExpr}, retention=${this.retention}`);
  }

  onModuleDestroy() {
    this.job?.stop();
  }

  async listDumps() {
    const rows = await this.prisma.databaseDump.findMany({
      orderBy: { startedAt: 'desc' },
      take: 200,
    });
    const items = rows.map(row => this.serialize(row));
    const totalSizeBytes = items.reduce((sum, row) => sum + row.sizeBytes, 0);

    return {
      config: {
        autoEnabled: this.autoEnabled,
        cron: this.cronExpr,
        scheduleLabel: this.scheduleLabel,
        retention: this.retention,
        dumpDir: this.dumpDir,
        format: 'custom',
        storageMode: 'server',
      },
      summary: {
        total: items.length,
        successful: items.filter(row => row.status === 'SUCCESS').length,
        failed: items.filter(row => row.status === 'FAILED').length,
        running: items.filter(row => row.status === 'RUNNING').length,
        totalSizeBytes,
      },
      items,
    };
  }

  async createDump(trigger: DumpTrigger = 'MANUAL', user?: DumpUser) {
    if (this.running) throw new ConflictException('Boshqa dump jarayoni hali tugamagan');

    const run = this.createDumpInternal(trigger, user);
    this.running = run.finally(() => { this.running = null; });
    return this.running;
  }

  async getDownload(id: string) {
    const row = await this.prisma.databaseDump.findUnique({ where: { id } });
    if (!row || row.status !== 'SUCCESS') throw new NotFoundException('Tayyor dump topilmadi');

    const resolved = path.resolve(row.filePath);
    const base = this.dumpDir.endsWith(path.sep) ? this.dumpDir : `${this.dumpDir}${path.sep}`;
    if (!resolved.startsWith(base)) throw new NotFoundException('Dump fayli ruxsat etilgan joyda emas');

    try {
      await fs.access(resolved);
    } catch {
      throw new NotFoundException('Dump fayli diskda topilmadi');
    }

    return {
      filename: row.filename,
      mime: 'application/octet-stream',
      stream: createReadStream(resolved),
    };
  }

  async deleteDump(id: string) {
    const row = await this.prisma.databaseDump.findUnique({ where: { id } });
    if (!row) throw new NotFoundException('Dump topilmadi');
    if (row.status === 'RUNNING') throw new ConflictException('Ishlayotgan dumpni o\'chirib bo\'lmaydi');

    await this.removeFile(row.filePath);
    await this.prisma.databaseDump.delete({ where: { id } });
    return { ok: true };
  }

  private async createDumpInternal(trigger: DumpTrigger, user?: DumpUser) {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) throw new InternalServerErrorException('DATABASE_URL sozlanmagan');

    await fs.mkdir(this.dumpDir, { recursive: true });

    const startedAt = new Date();
    const filename = this.fileName(startedAt, trigger);
    const filePath = path.join(this.dumpDir, filename);
    const row = await this.prisma.databaseDump.create({
      data: {
        filename,
        filePath,
        format: 'custom',
        status: 'RUNNING',
        trigger,
        createdById: user?.id || null,
        createdByName: user?.username || null,
        startedAt,
      },
    });

    try {
      await this.runPgDump(databaseUrl, filePath);
      const [stat, checksum] = await Promise.all([
        fs.stat(filePath),
        this.sha256File(filePath),
      ]);
      const saved = await this.prisma.databaseDump.update({
        where: { id: row.id },
        data: {
          status: 'SUCCESS',
          sizeBytes: BigInt(stat.size),
          checksumSha256: checksum,
          finishedAt: new Date(),
          errorMessage: null,
        },
      });
      await this.purgeOldDumps();
      return this.serialize(saved);
    } catch (err) {
      const message = this.errorMessage(err);
      await this.removeFile(filePath);
      await this.prisma.databaseDump.update({
        where: { id: row.id },
        data: {
          status: 'FAILED',
          errorMessage: message,
          finishedAt: new Date(),
        },
      }).catch(() => {});
      throw new InternalServerErrorException(message);
    }
  }

  private runPgDump(databaseUrl: string, filePath: string): Promise<void> {
    const { env, database } = this.pgEnv(databaseUrl);
    const args = [
      '--format=custom',
      '--no-owner',
      '--no-privileges',
      '--file',
      filePath,
      database,
    ];

    return new Promise((resolve, reject) => {
      const child = spawn(this.pgDumpBin, args, {
        env: { ...process.env, ...env },
        stdio: ['ignore', 'ignore', 'pipe'],
      });
      let stderr = '';
      child.stderr?.on('data', chunk => {
        stderr += String(chunk);
        if (stderr.length > 4000) stderr = stderr.slice(-4000);
      });
      child.on('error', reject);
      child.on('close', code => {
        if (code === 0) resolve();
        else reject(new Error(stderr.trim() || `pg_dump exited with code ${code}`));
      });
    });
  }

  private pgEnv(databaseUrl: string) {
    const parsed = new URL(databaseUrl);
    const database = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
    if (!database) throw new Error('DATABASE_URL ichida database nomi yo\'q');
    const env: Record<string, string> = {
      PGHOST: parsed.hostname,
      PGDATABASE: database,
    };
    if (parsed.port) env['PGPORT'] = parsed.port;
    if (parsed.username) env['PGUSER'] = decodeURIComponent(parsed.username);
    if (parsed.password) env['PGPASSWORD'] = decodeURIComponent(parsed.password);
    return { env, database };
  }

  private async purgeOldDumps() {
    const rows = await this.prisma.databaseDump.findMany({
      where: { status: 'SUCCESS' },
      orderBy: { startedAt: 'desc' },
    });
    const stale = rows.slice(this.retention);
    for (const row of stale) {
      await this.removeFile(row.filePath);
      await this.prisma.databaseDump.delete({ where: { id: row.id } }).catch(() => {});
    }
  }

  private async removeFile(filePath: string) {
    try {
      await fs.unlink(filePath);
    } catch (err: any) {
      if (err?.code !== 'ENOENT') throw err;
    }
  }

  private async sha256File(filePath: string): Promise<string> {
    const hash = createHash('sha256');
    return new Promise((resolve, reject) => {
      const stream = createReadStream(filePath);
      stream.on('data', chunk => hash.update(chunk));
      stream.on('error', reject);
      stream.on('end', () => resolve(hash.digest('hex')));
    });
  }

  private fileName(date: Date, trigger: DumpTrigger) {
    const stamp = date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
    return `cms_detector_${stamp}_${trigger.toLowerCase()}.dump`;
  }

  private describeCron(expr: string) {
    const parts = expr.trim().replace(/\s+/g, ' ').split(' ');
    if (parts.length !== 6) return 'Custom cron';

    const [sec, min, hour, day, month, weekday] = parts;
    const hh = String(Number(hour)).padStart(2, '0');
    const mm = String(Number(min)).padStart(2, '0');
    const dayNumber = Number(day);
    const timeReady = sec === '0' && Number.isFinite(Number(hour)) && Number.isFinite(Number(min));

    if (timeReady && month === '*' && weekday === '*' && day === '*') {
      return `Har kuni ${hh}:${mm}`;
    }

    if (timeReady && month === '*' && weekday === '*' && Number.isInteger(dayNumber) && dayNumber >= 1 && dayNumber <= 31) {
      return `Har oy ${dayNumber}-kuni ${hh}:${mm}`;
    }

    return 'Custom cron';
  }

  private serialize(row: any) {
    const sizeBytes = row.sizeBytes == null ? 0 : Number(row.sizeBytes);
    return {
      id: row.id,
      filename: row.filename,
      format: row.format,
      status: row.status,
      trigger: row.trigger,
      sizeBytes,
      checksumSha256: row.checksumSha256,
      errorMessage: row.errorMessage,
      createdById: row.createdById,
      createdByName: row.createdByName,
      startedAt: row.startedAt?.toISOString?.() || row.startedAt,
      finishedAt: row.finishedAt?.toISOString?.() || row.finishedAt || null,
      createdAt: row.createdAt?.toISOString?.() || row.createdAt,
    };
  }

  private errorMessage(err: unknown): string {
    const raw = err instanceof Error ? err.message : String(err);
    return raw.length > 600 ? `${raw.slice(0, 600)}...` : raw;
  }
}
