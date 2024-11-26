import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'pg';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(@Inject('DATABASE_POOL') private readonly pool: Pool) {}

  async findOneByUsername(username: string): Promise<any> {
    const result = await this.pool.query(
      '    SELECT \n' +
        '      users.id, \n' +
        '      users.username, \n' +
        '      tokens.access_token, \n' +
        '      tokens.refresh_token \n' +
        '    FROM \n' +
        '      users\n' +
        '    INNER JOIN \n' +
        '      tokens \n' +
        '    ON \n' +
        '      users.id = tokens.user_id\n' +
        '    WHERE \n' +
        '      users.username = $1',
      [username],
    );
    return result.rows[0];
  }

  async findPasswordUsername(username: string): Promise<any> {
    const result = await this.pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username],
    );
    return result.rows[0];
  }

  async createUser(username: string, password: string): Promise<void> {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await this.pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashedPassword],
    );
  }

  async validatePassword(username: string, password: string): Promise<boolean> {
    const result = await this.pool.query(
      'SELECT password FROM users WHERE username = $1',
      [username],
    );

    if (result.rowCount === 0) {
      return false;
    }

    const hashedPassword = result.rows[0].password;
    return bcrypt.compare(password, hashedPassword);
  }

  async deleteUser(username: string): Promise<void> {
    await this.pool.query('DELETE FROM users WHERE username = $1', [username]);
  }
}
