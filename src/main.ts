import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { UsersService } from './users/users.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: ['http://localhost:4200', 'http://127.0.0.1:4200', 'http://10.10.80.31'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });
  app.setGlobalPrefix('api');
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,    // DTO da yo'q maydonlarni o'chiradi
      transform: true, // Turlarni avtomatik konvertatsiya qiladi
  }));

  // Default admin yaratish
  const usersService = app.get(UsersService);
  await usersService.seedAdmin();

  await app.listen(3000, '0.0.0.0');
  console.log('🚀 http://localhost:topvol :)/api');
}
bootstrap();
