import { Container } from '@cloudflare/containers';
import { Hono } from 'hono';

export class MyContainer extends Container {
  async fetch(request: Request): Promise<Response> {
    const app = new Hono();

    app.get('/', (c) => c.text('Hello from Cloudflare Container!'));
    app.get('/ping', (c) => c.json({ message: 'pong' }));

    return app.fetch(request);
  }
}
