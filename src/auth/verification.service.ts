import { Inject, Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import Redis from 'ioredis';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class VerificationService {
  constructor(
    private readonly mailerService: MailerService,
    @Inject('REDIS_CLIENT') private readonly redis: Redis,
    private prisma: PrismaService,
  ) {}

  async sendVerificationCode(email: string) {
    const code = this.generateCode();

    await this.redis.set(`email-code:${email}`, code, 'EX', 180); // 3 минуты

    await this.mailerService.sendMail({
      to: email,
      template: 'confirm',
      subject: 'Your Verification Code',
      text: `Your verification code is: ${code}`,
      context: {
        code: code,
      },
    });
  }

  async verifyCode(email: string, code: string): Promise<boolean> {
    const storedCode = await this.redis.get(`email-code:${email}`);

    if (!storedCode) {
      return false;
    }

    if (storedCode !== code) {
      return false;
    }

    await this.prisma.user.update({
      where: { email },
      data: { emailVerified: true },
    });

    await this.redis.del(`email-code:${email}`);

    return true;
  }

  async resendVerificationCode(email: string): Promise<void> {
    await this.sendVerificationCode(email);
  }

  private generateCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-значный код
  }
}
