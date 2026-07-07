import './env-loader';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { UsersService } from './users/users.service';
import { json, urlencoded } from 'express';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bodyParser: false });

  app.use(json({ limit: '50mb' }));
  app.use(urlencoded({ limit: '50mb', extended: true }));

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

  const port = Number(process.env.PORT || 3001);
  await app.listen(port, '0.0.0.0');
  console.log(`API listening on http://localhost:${port}/api`);
}
bootstrap();
