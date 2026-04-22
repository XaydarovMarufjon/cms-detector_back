import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ?? 3000);
  app.useGlobalPipes(new ValidationPipe({
  whitelist: true,    // DTO da yo'q maydonlarni o'chiradi
  transform: true,    // Turlarni avtomatik konvertatsiya qiladi
}));
}
bootstrap();
