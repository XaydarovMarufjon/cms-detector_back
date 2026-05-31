import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

type CreateTaskDto = {
  title: string;
  description?: string;
  source?: string;
  priority?: string;
  dueDate?: string | null;
  websiteId?: string | null;
  assigneeId?: string | null;
};

type UpdateTaskDto = Partial<CreateTaskDto> & {
  status?: string;
};

@Injectable()
export class TasksService {
  constructor(private readonly prisma: PrismaService) {}

  findAll(filter: { status?: string; assigneeId?: string; websiteId?: string }) {
    return this.prisma.securityTask.findMany({
      where: {
        ...(filter.status ? { status: filter.status } : {}),
        ...(filter.assigneeId ? { assigneeId: filter.assigneeId } : {}),
        ...(filter.websiteId ? { websiteId: filter.websiteId } : {}),
      },
      include: this.includes(),
      orderBy: [{ status: 'asc' }, { updatedAt: 'desc' }],
    });
  }

  assignees() {
    return this.prisma.user.findMany({
      select: { id: true, username: true, role: true, createdAt: true },
      orderBy: { username: 'asc' },
    });
  }

  create(input: CreateTaskDto, createdById?: string) {
    const title = input.title?.trim();
    if (!title) throw new BadRequestException('Vazifa nomi kerak');

    return this.prisma.securityTask.create({
      data: {
        title,
        description: input.description?.trim() || null,
        source: this.cleanSource(input.source),
        priority: this.cleanPriority(input.priority),
        dueDate: input.dueDate ? new Date(input.dueDate) : null,
        websiteId: input.websiteId || null,
        assigneeId: input.assigneeId || null,
        createdById: createdById || null,
      },
      include: this.includes(),
    });
  }

  update(id: string, input: UpdateTaskDto) {
    const data: Record<string, unknown> = {};

    if (input.title !== undefined) {
      const title = input.title.trim();
      if (!title) throw new BadRequestException('Vazifa nomi kerak');
      data['title'] = title;
    }
    if (input.description !== undefined) data['description'] = input.description?.trim() || null;
    if (input.source !== undefined) data['source'] = this.cleanSource(input.source);
    if (input.priority !== undefined) data['priority'] = this.cleanPriority(input.priority);
    if (input.status !== undefined) data['status'] = this.cleanStatus(input.status);
    if (input.dueDate !== undefined) data['dueDate'] = input.dueDate ? new Date(input.dueDate) : null;
    if (input.websiteId !== undefined) data['websiteId'] = input.websiteId || null;
    if (input.assigneeId !== undefined) data['assigneeId'] = input.assigneeId || null;

    return this.prisma.securityTask.update({
      where: { id },
      data,
      include: this.includes(),
    });
  }

  remove(id: string) {
    return this.prisma.securityTask.delete({ where: { id } });
  }

  private includes() {
    return {
      website: { select: { id: true, url: true, label: true } },
      assignee: { select: { id: true, username: true, role: true } },
      createdBy: { select: { id: true, username: true, role: true } },
    };
  }

  private cleanPriority(priority?: string): string {
    const value = (priority || 'MEDIUM').toUpperCase();
    return ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(value) ? value : 'MEDIUM';
  }

  private cleanStatus(status?: string): string {
    const value = (status || 'OPEN').toUpperCase();
    return ['OPEN', 'IN_PROGRESS', 'DONE', 'CANCELLED'].includes(value) ? value : 'OPEN';
  }

  private cleanSource(source?: string): string {
    const value = (source || 'MANUAL').toUpperCase();
    return ['MANUAL', 'CVE', 'PORT', 'SUBDOMAIN', 'SSL', 'CMS'].includes(value) ? value : 'MANUAL';
  }
}
