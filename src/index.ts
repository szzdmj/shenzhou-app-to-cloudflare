import { Hono } from 'hono';

type Env = {
  MY_CONTAINER: DurableObjectNamespace;
};

export class MyContainer {} // 可为空实现

const app = new Hono<{ Bindings: Env }>();

app.get('/health', (c) => c.text('OK'));

app.all('*', async (c) => {
  const newRequest = new Request(c.req.raw, {
    headers: c.req.raw.headers,
    method: c.req.method,
    body: c.req.raw.body
  });

  return await c.env.MY_CONTAINER.fetch(newRequest);
});

export default {
  fetch: app.fetch
};
