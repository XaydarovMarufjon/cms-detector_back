import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ScannerModule } from './scanner/scanner.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { AlertsModule } from './alerts/alerts.module';
import { CallsModule } from './calls/calls.module';
import { LogsModule } from './logs/logs.module';
import { AuditInterceptor } from './logs/audit.interceptor';
import { TasksModule } from './tasks/tasks.module';
import { ImageModerationModule } from './image-moderation/image-moderation.module';

@Module({
  imports: [
    PrismaModule,
    LogsModule,
    AuthModule,
    UsersModule,
    ScannerModule,
    AlertsModule,
    CallsModule,
    TasksModule,
    ImageModerationModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    { provide: APP_INTERCEPTOR, useClass: AuditInterceptor },
  ],
})
export class AppModule { }
