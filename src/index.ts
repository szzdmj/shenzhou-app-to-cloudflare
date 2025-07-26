import { Hono } from 'hono';
import { MyContainer } from './my-container';

export class MyContainer {
  // Durable Object class 必须存在
}

type Env = {
  MY_CONTAINER: Fetcher
  KV: KVNamespace
}

const app = new Hono<{ Bindings: Env }>();

app.get('/health', (c) => c.text('OK'));

app.all('*', async (c) => {
  const newRequest = new Request(c.req.raw, {
    headers: c.req.raw.headers,
  });
  return c.env.MY_CONTAINER.fetch(newRequest);
});

export default app;
export { MyContainer };
