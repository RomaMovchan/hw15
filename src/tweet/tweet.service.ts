import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'pg';

@Injectable()
export class TweetService {
  constructor(@Inject('DATABASE_POOL') private readonly pool: Pool) {}

  async getAllTweets(): Promise<any> {
    const result = await this.pool.query('SELECT * FROM tweets');
    return result.rows;
  }

  async createTweet(username: string, content: string): Promise<any> {
    const result = await this.pool.query(
      'INSERT INTO tweets (username, content) VALUES ($1, $2) RETURNING *',
      [username, content],
    );
    return result.rows[0];
  }

  async updateTweet(id: number, content: string): Promise<any> {
    const result = await this.pool.query(
      'UPDATE tweets SET content = $1 WHERE id = $2 RETURNING *',
      [content, id],
    );
    return result.rows[0];
  }

  async deleteTweet(id: number): Promise<any> {
    await this.pool.query('DELETE FROM tweets WHERE id = $1', [id]);
    return { message: `Tweet with id ${id} deleted successfully` };
  }

  async findTweetById(id: number): Promise<any> {
    const result = await this.pool.query('SELECT * FROM tweets WHERE id = $1', [
      id,
    ]);
    return result.rows[0];
  }
}
