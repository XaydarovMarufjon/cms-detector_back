import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ScannerModule } from './scanner/scanner.module';

@Module({
  imports: [ScannerModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
