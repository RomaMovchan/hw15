import { Controller, Get, Param, Post, Body } from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get(':username')
  async findOne(@Param('username') username: string) {
    return this.usersService.findOneByUsername(username);
  }

  @Post()
  async create(@Body() body: { username: string; password: string }) {
    await this.usersService.createUser(body.username, body.password);
    return { message: 'User created successfully' };
  }
}
