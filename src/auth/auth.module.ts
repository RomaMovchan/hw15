import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './services/auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { TokensService } from './services/tokens.service';
import { WebsocketGateway } from './guards/websocket.gateway';

@Module({
  imports: [
    UsersModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'secret',
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, TokensService, WebsocketGateway],
  exports: [TokensService],
})
export class AuthModule {}
