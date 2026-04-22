import {
  Controller, Get, Post,
  Param, Body, HttpCode
} from '@nestjs/common';
import { ScannerService } from './scanner.service';
import { ScanWebsiteDto } from './dto/scan.dto';

@Controller('scanner') // Barcha route lar /scanner/ bilan boshlanadi
export class ScannerController {
  constructor(private readonly scanner: ScannerService) {}

  // GET /scanner/results
  @Get('results')
  getResults() {
    return this.scanner.getLatestResults();
  }

  // POST /scanner/scan
  // Body: { "websiteId": "uuid", "url": "https://..." }
  @Post('scan')
  @HttpCode(200)
  scanOne(@Body() dto: ScanWebsiteDto) {
    return this.scanner.scanOne(dto.websiteId, dto.url);
  }

  // POST /scanner/scan-all — barcha saytlarni skanerlash
  @Post('scan-all')
  @HttpCode(200)
  scanAll() {
    return this.scanner.scanAll();
  }
}