import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable() // ← DI ga qo'shish uchun shart
export class PrismaService extends PrismaClient
  implements OnModuleInit {

  // Ilova ishga tushganda DB ga ulanadi
  async onModuleInit() {
    await this.$connect();
  }
}