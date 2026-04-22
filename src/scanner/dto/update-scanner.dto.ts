import { PartialType } from '@nestjs/mapped-types';
import { CreateScannerDto } from './scan.dto';

export class UpdateScannerDto extends PartialType(CreateScannerDto) { }
