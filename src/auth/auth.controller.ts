import { Body, Controller, Post, BadRequestException, HttpCode, Res, Req, Get, UseGuards} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { VerificationService } from './verification.service';
import { Request, Response } from 'express';
import { AuthGuard } from '@nestjs/passport';

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
  @HttpCode(200)
  login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    return this.authService.login(dto, res);
  }

  @Post('logout')
  @HttpCode(200)
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.authService.logout(req, res);
  }

  @Post('refresh')
  @HttpCode(200)
  Refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.authService.refresh(req, res);
  }

  @Get('me')
  @HttpCode(200)
  Me(@Req() req: Request) {
    return this.authService.me(req);
  }

  @Post('forgot-password')
  @HttpCode(200)
  ForgotPassword(@Body() body: { email: string }) {
    return this.authService.forgotPassword(body.email);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Просто редиректит на Google
  }

  @Get('google/redirect')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req, @Res({ passthrough: true }) res: Response) {
    const user = req.user;

    const tokens = await this.authService.loginWithOAuth(user, res);

    res.redirect(`http://localhost:5173/oauth/callback?access_token=${tokens.access_token}`);
  }
}
