import { IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @IsString()
  token: string;

  @IsString()
  @MinLength(8, { message: 'Пароль должен быть минимум 8 символов' })
  newPassword: string;
}
