import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => ({
  secret: process.env.JWT_SECRET || 'dev-secret-key-change-in-production',
  expirationTime: process.env.JWT_EXPIRATION || '15m',
  refreshTokenExpiration: process.env.JWT_REFRESH_EXPIRATION || '7d',
  issuer: process.env.JWT_ISSUER || 'mags-ai-studio',
  audience: process.env.JWT_AUDIENCE || 'mags-ai-users',
}));
