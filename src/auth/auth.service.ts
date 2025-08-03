// src/auth/auth.service.ts
import { Injectable, ConflictException, UnauthorizedException, BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { VerificationService } from './verification.service';
import { Request, Response } from 'express';
import Redis from 'ioredis';
import { Inject } from '@nestjs/common';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private readonly verificationService: VerificationService,
    @Inject('REDIS_CLIENT') private readonly redis: Redis,
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

    await this.verificationService.sendVerificationCode(dto.email);

    // Возвращаем минимум данных
    return {
      message: 'User created',
      user: {
        id: user.id,
        email: user.email,
      },
    };
  }

  async logout(req: Request, res: Response) {
    const refreshToken = req.cookies['refresh_token'];

    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token');
    }

    // Ищем пользователя по refresh токену
    const user = await this.prisma.user.findFirst({
      where: { refreshToken },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Удаляем токен из базы
    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: null },
    });

    // Удаляем куку на клиенте
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
    });

    return { message: 'Logged out successfully' };
  }

  // Логин
  async login(dto: LoginDto, res: Response) {
    // Ищем пользователя по email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.emailVerified) {
      throw new UnauthorizedException('Email not verified');
    }

    if (!user || !user.password) {
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
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '15m',
    });

    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: '7d',
    });

    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken },
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { access_token: accessToken };
  }

  async refresh(req: Request, res: Response) {
    const refreshToken = req.cookies['refresh_token'];

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(refreshToken);
    } catch (e) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user || user.refreshToken !== refreshToken) {
      throw new UnauthorizedException('Refresh token mismatch');
    }

    const newPayload = {
      sub: user.id,
      email: user.email,
    };

    const newAccessToken = this.jwtService.sign(newPayload, {
      expiresIn: '15m',
    });

    const newRefreshToken = this.jwtService.sign(newPayload, {
      expiresIn: '7d',
    });

    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: newRefreshToken },
    });

    res.cookie('refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
    });

    return { access_token: newAccessToken };
  }

  async me(req: Request) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or malformed token');
    }

    const accessToken = authHeader.replace('Bearer ', '');

    let payload: any;
    try {
      payload = this.jwtService.verify(accessToken);
    } catch (err) {
      throw new UnauthorizedException('Invalid token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return {
      id: user.id,
      email: user.email,
      firstname: user.firstname,
      lastname: user.lastname,
    };
  }

  async loginWithOAuth(userData: { email: string; firstName: string; lastName: string }, res: Response) {
    let user = await this.prisma.user.findUnique({
      where: { email: userData.email },
    });

    if (!user) {
      user = await this.prisma.user.create({
        data: {
          email: userData.email,
          firstname: userData.firstName,
          lastname: userData.lastName,
          emailVerified: true,
          // provider: 'google',
        },
      });
    }

    const payload = { sub: user.id, email: user.email };

    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken },
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { access_token: accessToken };
  }

  async forgotPassword(email: string) {
    const user = await this.prisma.user.findUnique({
      where: { email: email },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    await this.verificationService.sendPasswordResetLink(email);

    return {
      success: true,
    };
  }

  async resetPassword(token: string, password: string) {
    if (!password || password.length < 8) {
      throw new BadRequestException('Неверный формат пароля');
    }

    const userEmail = await this.verificationService.verifyPasswordToken(token);

    if (!userEmail) {
      throw new UnauthorizedException('Неверный или просроченный токен');
    }

    const user = await this.prisma.user.findUnique({
      where: { email: userEmail },
    });

    if (!user) {
      throw new NotFoundException('Пользователь не найден');
    }

    const hash = await bcrypt.hash(password, 10);

    await this.prisma.user.update({
      where: { email: userEmail },
      data: { password: hash },
    });

    // ← удаляем токен после успешного сброса
    await this.redis.del(`reset-password-token:${token}`);

    return {
      success: true,
      message: 'Пароль успешно обновлён',
    };
  }
}
