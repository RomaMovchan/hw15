import { WebSocketGateway, SubscribeMessage, MessageBody, ConnectedSocket, OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect } from '@nestjs/websockets';
import { Socket, Server } from 'socket.io';
import { JwtService } from '@nestjs/jwt';

@WebSocketGateway({ cors: { origin: '*' } })
export class WebsocketGateway implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect {
  constructor(private readonly jwtService: JwtService) {}

  afterInit(server: Server) {
    console.log('WebSocket Gateway Initialized');
  }

  handleConnection(client: Socket) {
    console.log('Client connected:', client.id);
  }

  handleDisconnect(client: Socket) {
    console.log('Client disconnected:', client.id);
  }

  @SubscribeMessage('checkToken')
  async handleTokenCheck(@MessageBody() data: { token: string }, @ConnectedSocket() client: Socket) {
    try {
      const decoded = this.jwtService.verify(data.token);

      client.emit('tokenStatus', { valid: true, message: 'Token is valid' });
    } catch (error) {
      client.emit('tokenStatus', { valid: false, message: 'Invalid or expired token' });
      client.disconnect();
    }
  }
}
