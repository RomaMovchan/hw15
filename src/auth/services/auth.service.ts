import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../../users/users.service';
import { TokensService } from './tokens.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly usersService: UsersService,
    private readonly tokensService: TokensService,
  ) {}

  async validateUser(username: string, password: string): Promise<any> {
    const user = await this.usersService.findPasswordUsername(username);
    if (!user) return null;

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (passwordMatch) {
      return user;
    }
    return null;
  }

  async validateToken(token: string): Promise<boolean> {
    try {
      const decoded = this.jwtService.verify(token); // It will throw an error if the token is invalid
      return true;
    } catch (error) {
      return false;
    }
  }

  async login(user: any) {
    const token = await this.tokensService.findAccessTokenUserId(user.id);
    if (token) {
      const isAccessTokenValid = this.validateToken(token.access_token);
      const isRefreshTokenValid = this.validateToken(token.access_token);

      if (isAccessTokenValid && isRefreshTokenValid) {
        return {
          access_token: token.access_token,
          refresh_token: token.refresh_token,
        }
      } else {
        await this.tokensService.deleteAccessToken(token.access_token);
        await this.tokensService.deleteRefreshToken(token.access_token);
      }
    }

    const payload = { username: user.username, sub: user.id };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '3h' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    await this.tokensService.saveTokens(user.id, accessToken, refreshToken);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async refreshAccessToken(
    refreshToken: string,
  ): Promise<{ access_token: string }> {
    const storedToken = await this.tokensService.findRefreshToken(refreshToken);

    if (!storedToken) {
      throw new Error('Refresh token not found');
    }

    try {
      const decoded = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_SECRET,
      });

      const newAccessToken = this.jwtService.sign(
        { username: decoded.username, sub: decoded.sub },
        { expiresIn: '15m', secret: process.env.JWT_SECRET },
      );

      await this.tokensService.saveTokens(
        decoded.sub,
        newAccessToken,
        refreshToken,
      );

      return { access_token: newAccessToken };
    } catch (err) {
      throw new Error('Invalid or expired refresh token');
    }
  }

  async logout(accessToken: string): Promise<void> {
    await this.tokensService.deleteAccessToken(accessToken);
  }
}
