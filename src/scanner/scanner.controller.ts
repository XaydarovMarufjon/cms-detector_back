import {
  Controller, Get, Post,
  Param, Body, HttpCode,
  Delete, Patch
} from '@nestjs/common';
import { ScannerService } from './scanner.service';
import { ScanWebsiteDto } from './dto/scan.dto';
import { PrismaService } from 'src/prisma/prisma.service';

@Controller('scanner') // Barcha route lar /scanner/ bilan boshlanadi
export class ScannerController {
  constructor(
    private readonly scanner: ScannerService,
    private readonly prisma: PrismaService) { }

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

  @Get('websites')
  getAllWebsites() {
    return this.prisma.website.findMany({
      orderBy: { createdAt: 'desc' },
    });
  }

  @Post('websites')
  createWebsite(@Body() body: { url: string; label?: string }) {
    return this.prisma.website.create({
      data: { url: body.url, label: body.label },
    });
  }

  @Delete('websites/:id')
  async deleteWebsite(@Param('id') id: string) {
    // Avval scan natijalarini o'chirish
    await this.prisma.scanResult.deleteMany({
      where: { websiteId: id },
    });

    // Keyin saytni o'chirish
    return this.prisma.website.delete({
      where: { id },
    });
  }


  @Patch('websites/:id')
  async updateWebsite(
    @Param('id') id: string,
    @Body() body: { url?: string; label?: string }
  ) {
    return this.prisma.website.update({
      where: { id },
      data: {
        url: body.url,
        label: body.label,
      },
    });
  }

}