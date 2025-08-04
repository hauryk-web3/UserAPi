// src/redis/redis.module.ts
import { Module, Global } from '@nestjs/common';
import Redis from 'ioredis';

@Global()
@Module({
  providers: [
    {
      provide: 'REDIS_CLIENT',
      useFactory: async () => {
        const host = process.env.REDIS_HOST || 'localhost';
        const port = Number(process.env.REDIS_PORT) || 6379;
        return new Redis({ host, port });
      },
    },
  ],
  exports: ['REDIS_CLIENT'],
})
export class RedisModule {}

