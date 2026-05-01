import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ScannerModule } from './scanner/scanner.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [ScannerModule,
    PrismaModule,
    AuthModule,
    UsersModule,
    ScannerModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
