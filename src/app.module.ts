import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { DatabaseModule } from './database/database.module';
import { TweetModule } from './tweet/tweet.module';

@Module({
  imports: [DatabaseModule, AuthModule, UsersModule, TweetModule],
})
export class AppModule {}
