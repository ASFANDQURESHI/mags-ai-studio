import { registerAs } from '@nestjs/config';

export default registerAs('security', () => ({
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '10'),
  passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH || '8'),
  maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
  lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || '900'), // 15 minutes
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  enableHttpOnly: process.env.COOKIE_HTTP_ONLY === 'true',
  enableSecure: process.env.COOKIE_SECURE === 'true',
  sameSite: process.env.COOKIE_SAME_SITE || 'strict',
}));
