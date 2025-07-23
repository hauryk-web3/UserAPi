// src/auth/auth.service.ts
import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  // Регистрация
  async register(dto: RegisterDto) {
    // Проверяем, есть ли пользователь с таким email
    const userExists = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (userExists) {
      throw new ConflictException('User already exists');
    }

    // Хешируем пароль
    const hash = await bcrypt.hash(dto.password, 10);

    // Создаем пользователя в БД
    const user = await this.prisma.user.create({
      data: {
        firstname: dto.firstname,
        lastname: dto.lastname,
        email: dto.email,
        password: hash,
      },
    });

    // Возвращаем минимум данных
    return {
      message: 'User created',
      user: {
        id: user.id,
        email: user.email,
      },
    };
  }

  // Логин
  async login(dto: LoginDto) {
    // Ищем пользователя по email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Проверяем пароль
    const isMatch = await bcrypt.compare(dto.password, user.password);

    if (!isMatch) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Формируем JWT payload
    const payload = { sub: user.id, email: user.email };

    // Генерируем токен
    const token = this.jwtService.sign(payload);

    return { access_token: token };
  }
}
