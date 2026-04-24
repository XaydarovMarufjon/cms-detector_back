import { IsString, IsUrl, IsUUID } from 'class-validator';

export class ScanWebsiteDto {
    @IsUUID()
    websiteId!: string;

    @IsUrl()          // URL formatini tekshiradi
    url!: string;
}
