import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Request,
  Body,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import { TweetService } from './tweet.service';
import { JwtAuthGuard } from '../auth/guards/oauth2.guard';

@UseGuards(JwtAuthGuard)
@Controller('tweets')
export class TweetController {
  constructor(private readonly tweetService: TweetService) {}

  @Get()
  async getAllTweets() {
    return this.tweetService.getAllTweets();
  }

  @Post()
  async createTweet(@Body() body: { username: string; content: string }) {
    return this.tweetService.createTweet(body.username, body.content);
  }

  @Put(':id')
  async updateTweet(
    @Param('id') id: number,
    @Body() body: { content: string },
  ) {
    return this.tweetService.updateTweet(id, body.content);
  }

  @Delete(':id')
  async deleteTweet(@Param('id') id: number, @Request() req: any) {
    const user = req.user;

    const tweet = await this.tweetService.findTweetById(id);
    if (!tweet) {
      throw new UnauthorizedException('Tweet not found');
    }

    if (tweet.username !== user.username) {
      throw new UnauthorizedException(
        'You are not authorized to delete this tweet',
      );
    }

    return this.tweetService.deleteTweet(id);
  }
}
