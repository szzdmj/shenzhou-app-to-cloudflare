import { Hono } from 'hono'
  
type Env = {
  MY_CONTAINER: DurableObjectNamespace
  KV: KVNamespace
}

export class MyContainer {
  // Durable Object class code, if needed; 可留空（让 container fetch 执行）
}

const app = new Hono<{ Bindings: Env }>()

app.get('/health', (c) => c.text('OK'))

app.all('*', async (c) => {
  const newRequest = new Request(c.req.raw, {
    headers: c.req.raw.headers
  })
  return await c.env.MY_CONTAINER.fetch(newRequest)
})

export default {
  fetch: app.fetch
}
