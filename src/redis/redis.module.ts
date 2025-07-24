// src/redis/redis.module.ts
import { Module, Global } from '@nestjs/common';
import Redis from 'ioredis';
import { RedisTestService } from './redis-test.service';

@Global()
@Module({
  providers: [
    {
      provide: 'REDIS_CLIENT',
      useFactory: async () => {
        return new Redis({ host: 'localhost', port: 6379 });
      },
    },
    RedisTestService, // ← добавляем сервис
  ],
  exports: ['REDIS_CLIENT'],
})
export class RedisModule {}
