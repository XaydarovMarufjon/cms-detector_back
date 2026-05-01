// src/users/users.service.ts
import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async findByUsername(username: string) {
    return this.prisma.user.findUnique({ where: { username } });
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({
      where: { id },
      select: { id: true, username: true, role: true, createdAt: true },
    });
  }

  async findAll() {
    return this.prisma.user.findMany({
      select: { id: true, username: true, role: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  async create(username: string, password: string, role: 'ADMIN' | 'WORKER' | 'MONITORING') {
    const exists = await this.findByUsername(username);
    if (exists) throw new ConflictException('Bu username allaqachon mavjud');

    const hashed = await bcrypt.hash(password, 10);
    return this.prisma.user.create({
      data: { username, password: hashed, role },
      select: { id: true, username: true, role: true, createdAt: true },
    });
  }

  async update(id: string, data: { username?: string; password?: string; role?: string }) {
    const updateData: any = {};
    if (data.username) updateData.username = data.username;
    if (data.password) updateData.password = await bcrypt.hash(data.password, 10);
    if (data.role)     updateData.role     = data.role;

    return this.prisma.user.update({
      where: { id },
      data: updateData,
      select: { id: true, username: true, role: true, createdAt: true },
    });
  }

  async delete(id: string) {
    const user = await this.findById(id);
    if (!user) throw new NotFoundException('Foydalanuvchi topilmadi');
    return this.prisma.user.delete({ where: { id } });
  }

  // Default admin yaratish (birinchi ishga tushganda)
  async seedAdmin() {
    const existing = await this.prisma.user.count();
    if (existing === 0) {
      await this.create('admin', 'admin123', 'ADMIN');
      console.log('✅ Default admin yaratildi: admin / admin123');
    }
  }
}
