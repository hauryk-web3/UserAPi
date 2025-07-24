// src/redis/redis-test.service.ts
import { Inject, Injectable, OnModuleInit, Logger } from '@nestjs/common';
import Redis from 'ioredis';

@Injectable()
export class RedisTestService implements OnModuleInit {
  private readonly logger = new Logger(RedisTestService.name);

  constructor(
    @Inject('REDIS_CLIENT') private readonly redisClient: Redis,
  ) {}

  async onModuleInit() {
    try {
      const result = await this.redisClient.ping();
      this.logger.log(`Redis ping response: ${result}`);
    } catch (error) {
      this.logger.error('Redis ping failed:', error);
    }
  }
}
