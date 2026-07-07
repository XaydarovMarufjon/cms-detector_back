import { BadRequestException, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';

interface SyncColumn {
  id?: unknown;
  label?: unknown;
  width?: unknown;
}

interface SyncRow {
  id?: unknown;
  height?: unknown;
  cells?: unknown;
  styles?: unknown;
}

interface SyncSheet {
  id?: unknown;
  name?: unknown;
  workbookId?: unknown;
  workbookName?: unknown;
  columns?: SyncColumn[];
  rows?: SyncRow[];
}

interface SyncPayload {
  activeSheetId?: unknown;
  activeWorkbookId?: unknown;
  fileName?: unknown;
  sheets?: SyncSheet[];
}

interface NormalizedColumn {
  id: string;
  label: string;
  width: number;
}

interface NormalizedRow {
  externalId: string | null;
  rowIndex: number;
  cells: Record<string, string>;
  styles: Record<string, unknown> | null;
  raw: Record<string, unknown>;
}

interface NormalizedSheet {
  externalId: string;
  name: string;
  workbookId: string;
  workbookName: string;
  sheetIndex: number;
  active: boolean;
  columns: NormalizedColumn[];
  rows: NormalizedRow[];
}

@Injectable()
export class VulnerabilitiesService {
  constructor(private readonly prisma: PrismaService) {}

  async replaceSnapshot(payload: unknown) {
    const sheets = this.normalizeSheets(payload);
    const data = payload as SyncPayload;

    await this.prisma.$transaction(async tx => {
      await tx.vulnerabilityWorkbook.deleteMany({});

      const byWorkbook = new Map<string, NormalizedSheet[]>();
      for (const sheet of sheets) {
        const list = byWorkbook.get(sheet.workbookId) ?? [];
        list.push(sheet);
        byWorkbook.set(sheet.workbookId, list);
      }

      for (const [workbookId, workbookSheets] of byWorkbook.entries()) {
        const workbook = await tx.vulnerabilityWorkbook.create({
          data: {
            externalId: workbookId,
            name: workbookSheets[0]?.workbookName || 'Excel fayl',
            fileName: this.cleanString(data.fileName) || workbookSheets[0]?.workbookName || null,
            active: workbookId === this.cleanString(data.activeWorkbookId),
          },
        });

        for (const sheet of workbookSheets) {
          const createdSheet = await tx.vulnerabilitySheet.create({
            data: {
              externalId: sheet.externalId,
              workbookId: workbook.id,
              name: sheet.name,
              sheetIndex: sheet.sheetIndex,
              active: sheet.active,
              columns: sheet.columns as unknown as Prisma.InputJsonValue,
            },
          });

          if (sheet.rows.length) {
            await tx.vulnerabilityRow.createMany({
              data: sheet.rows.map(row => ({
                externalId: row.externalId,
                sheetId: createdSheet.id,
                rowIndex: row.rowIndex,
                cells: row.cells as unknown as Prisma.InputJsonValue,
                styles: row.styles as unknown as Prisma.InputJsonValue,
                raw: row.raw as unknown as Prisma.InputJsonValue,
              })),
            });
          }
        }
      }
    });

    return {
      workbooks: new Set(sheets.map(sheet => sheet.workbookId)).size,
      sheets: sheets.length,
      rows: sheets.reduce((sum, sheet) => sum + sheet.rows.length, 0),
    };
  }

  async listImports() {
    const workbooks = await this.prisma.vulnerabilityWorkbook.findMany({
      orderBy: { importedAt: 'desc' },
      include: {
        sheets: {
          orderBy: { sheetIndex: 'asc' },
          include: { _count: { select: { rows: true } } },
        },
      },
    });

    return workbooks.map(workbook => ({
      id: workbook.id,
      sourceId: workbook.externalId,
      name: workbook.name,
      fileName: workbook.fileName,
      active: workbook.active,
      importedAt: workbook.importedAt,
      updatedAt: workbook.updatedAt,
      sheets: workbook.sheets.map(sheet => ({
        id: sheet.id,
        sourceId: sheet.externalId,
        name: sheet.name,
        index: sheet.sheetIndex,
        active: sheet.active,
        rowCount: sheet._count.rows,
      })),
      rowCount: workbook.sheets.reduce((sum, sheet) => sum + sheet._count.rows, 0),
    }));
  }

  async exportAll() {
    const workbooks = await this.prisma.vulnerabilityWorkbook.findMany({
      orderBy: { importedAt: 'desc' },
      include: {
        sheets: {
          orderBy: { sheetIndex: 'asc' },
          include: {
            rows: { orderBy: { rowIndex: 'asc' } },
          },
        },
      },
    });

    const nested = workbooks.map(workbook => ({
      id: workbook.id,
      sourceId: workbook.externalId,
      name: workbook.name,
      fileName: workbook.fileName,
      active: workbook.active,
      importedAt: workbook.importedAt,
      updatedAt: workbook.updatedAt,
      sheets: workbook.sheets.map(sheet => ({
        id: sheet.id,
        sourceId: sheet.externalId,
        name: sheet.name,
        index: sheet.sheetIndex,
        active: sheet.active,
        columns: sheet.columns,
        importedAt: sheet.importedAt,
        updatedAt: sheet.updatedAt,
        rows: sheet.rows.map(row => ({
          id: row.id,
          sourceId: row.externalId,
          index: row.rowIndex,
          cells: row.cells,
          styles: row.styles,
          raw: row.raw,
          importedAt: row.importedAt,
          updatedAt: row.updatedAt,
        })),
      })),
    }));

    const rows = nested.flatMap(workbook => workbook.sheets.flatMap(sheet => {
      const columns = Array.isArray(sheet.columns) ? sheet.columns as unknown as NormalizedColumn[] : [];
      return sheet.rows.map(row => ({
        workbookId: workbook.id,
        workbookSourceId: workbook.sourceId,
        workbookName: workbook.name,
        sheetId: sheet.id,
        sheetSourceId: sheet.sourceId,
        sheetName: sheet.name,
        rowId: row.id,
        rowSourceId: row.sourceId,
        rowIndex: row.index,
        values: this.cellsByLabel(row.cells as Record<string, string>, columns),
        cells: row.cells,
        styles: row.styles,
        raw: row.raw,
      }));
    }));

    return {
      generatedAt: new Date().toISOString(),
      totalWorkbooks: nested.length,
      totalSheets: nested.reduce((sum, workbook) => sum + workbook.sheets.length, 0),
      totalRows: rows.length,
      workbooks: nested,
      rows,
    };
  }

  async exportRows() {
    const data = await this.exportAll();
    return {
      generatedAt: data.generatedAt,
      totalRows: data.totalRows,
      rows: data.rows,
    };
  }

  private normalizeSheets(payload: unknown): NormalizedSheet[] {
    if (!payload || typeof payload !== 'object') {
      throw new BadRequestException('Payload noto‘g‘ri');
    }
    const data = payload as SyncPayload;
    if (!Array.isArray(data.sheets)) return [];

    return data.sheets.map((sheet, sheetIndex) => {
      const columns = this.normalizeColumns(sheet.columns);
      const workbookId = this.cleanString(sheet.workbookId) || 'default-workbook';
      const externalId = this.cleanString(sheet.id) || `${workbookId}-sheet-${sheetIndex + 1}`;
      return {
        externalId,
        name: this.cleanString(sheet.name) || `Sheet ${sheetIndex + 1}`,
        workbookId,
        workbookName: this.cleanString(sheet.workbookName) || 'Excel fayl',
        sheetIndex,
        active: externalId === this.cleanString(data.activeSheetId),
        columns,
        rows: this.normalizeRows(sheet.rows, columns),
      };
    });
  }

  private normalizeColumns(columns: SyncColumn[] | undefined): NormalizedColumn[] {
    if (!Array.isArray(columns)) return [];
    return columns.map((column, index) => ({
      id: this.cleanString(column?.id) || `col_${index + 1}`,
      label: this.cleanString(column?.label) || `Ustun ${index + 1}`,
      width: this.clamp(Math.round(Number(column?.width) || 160), 48, 1200),
    }));
  }

  private normalizeRows(rows: SyncRow[] | undefined, columns: NormalizedColumn[]): NormalizedRow[] {
    if (!Array.isArray(rows)) return [];
    return rows
      .map((row, index) => {
        const cells = this.normalizeCells(row?.cells, columns);
        return {
          externalId: this.cleanString(row?.id) || null,
          rowIndex: index,
          cells,
          styles: this.normalizeRecord(row?.styles),
          raw: {
            height: this.clamp(Math.round(Number(row?.height) || 35), 1, 500),
          },
        };
      })
      .filter(row => Object.values(row.cells).some(value => value.trim()));
  }

  private normalizeCells(input: unknown, columns: NormalizedColumn[]): Record<string, string> {
    const raw = this.normalizeRecord(input) ?? {};
    const cells: Record<string, string> = {};
    for (const column of columns) {
      cells[column.id] = this.cleanString(raw[column.id]);
    }
    return cells;
  }

  private normalizeRecord(input: unknown): Record<string, unknown> | null {
    if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
    return Object.fromEntries(
      Object.entries(input as Record<string, unknown>)
        .filter(([key]) => typeof key === 'string' && key.length > 0)
        .map(([key, value]) => [key, this.jsonSafe(value)]),
    );
  }

  private cellsByLabel(cells: Record<string, string>, columns: NormalizedColumn[]): Record<string, string> {
    const out: Record<string, string> = {};
    for (const column of columns) {
      out[column.label || column.id] = cells[column.id] ?? '';
    }
    return out;
  }

  private cleanString(value: unknown): string {
    if (value === null || value === undefined) return '';
    return String(value).replace(/\s+/g, ' ').trim();
  }

  private jsonSafe(value: unknown): unknown {
    if (value === null || value === undefined) return null;
    if (['string', 'number', 'boolean'].includes(typeof value)) return value;
    if (Array.isArray(value)) return value.map(item => this.jsonSafe(item));
    if (typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>).map(([key, val]) => [key, this.jsonSafe(val)]),
      );
    }
    return String(value);
  }

  private clamp(value: number, min: number, max: number): number {
    return Math.min(Math.max(value, min), max);
  }
}
