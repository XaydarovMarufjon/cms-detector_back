import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: 'http://localhost:4200',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });
  app.setGlobalPrefix('api');
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,    // DTO da yo'q maydonlarni o'chiradi
    transform: true,    // Turlarni avtomatik konvertatsiya qiladi
  }));
  await app.listen(process.env.PORT ?? 3000);
  console.log('🚀 http://localhost:3000/api');
}
bootstrap();
