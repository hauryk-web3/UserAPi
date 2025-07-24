import { Body, Controller, Post, BadRequestException } from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { VerificationService } from './verification.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly verificationService: VerificationService,
  ) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('verify')
  async verifyCode(@Body() body: { email: string; code: string }) {
    const { email, code } = body;

    try {
      const isValid = await this.verificationService.verifyCode(email, code);
      if (!isValid) {
        throw new BadRequestException('Неверный код');
      }

      return { message: 'Email успешно подтверждён' };
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  @Post('resend-code')
  async resendCode(@Body() body: { email: string }) {
    try {
      await this.verificationService.resendVerificationCode(body.email);
      return { message: 'Код повторно отправлен на почту' };
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }
}
