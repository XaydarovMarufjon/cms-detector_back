import { PartialType } from '@nestjs/mapped-types';
import { ScanWebsiteDto } from './scan.dto';

export class UpdateScannerDto extends PartialType(ScanWebsiteDto) { }
