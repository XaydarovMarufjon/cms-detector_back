import {
  Body, Controller, Delete, Get, HttpCode, Param, Patch, Post, Query, UseGuards,
} from '@nestjs/common';
import { TasksService } from './tasks.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

@Controller('tasks')
@UseGuards(JwtAuthGuard, RolesGuard)
export class TasksController {
  constructor(private readonly tasks: TasksService) {}

  @Get()
  findAll(
    @Query('status') status?: string,
    @Query('assigneeId') assigneeId?: string,
    @Query('websiteId') websiteId?: string,
  ) {
    return this.tasks.findAll({ status, assigneeId, websiteId });
  }

  @Get('assignees')
  assignees() {
    return this.tasks.assignees();
  }

  @Post()
  @Roles('ADMIN', 'WORKER')
  create(
    @Body() body: {
      title: string;
      description?: string;
      source?: string;
      priority?: string;
      dueDate?: string | null;
      websiteId?: string | null;
      assigneeId?: string | null;
    },
    @CurrentUser() user: { id: string },
  ) {
    return this.tasks.create(body, user?.id);
  }

  @Patch(':id')
  @Roles('ADMIN', 'WORKER')
  update(
    @Param('id') id: string,
    @Body() body: {
      title?: string;
      description?: string;
      source?: string;
      status?: string;
      priority?: string;
      dueDate?: string | null;
      websiteId?: string | null;
      assigneeId?: string | null;
    },
  ) {
    return this.tasks.update(id, body);
  }

  @Delete(':id')
  @Roles('ADMIN')
  @HttpCode(200)
  remove(@Param('id') id: string) {
    return this.tasks.remove(id);
  }
}
