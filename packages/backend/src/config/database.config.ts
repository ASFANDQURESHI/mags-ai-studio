import { registerAs } from '@nestjs/config';

export default registerAs('database', () => ({
  url: process.env.DATABASE_URL,
  logging: process.env.DATABASE_LOGGING === 'true',
  synchronize: process.env.DATABASE_SYNC === 'true',
}));
