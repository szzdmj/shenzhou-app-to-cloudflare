import { Hono } from 'hono'

type Env = {
  MY_CONTAINER: DurableObjectNamespace
  KV: KVNamespace
}

export class MyContainer {} // 留空：请求将转发到 container

const app = new Hono<{ Bindings: Env }>()

app.get('/health', (c) => c.text('OK'))

app.all('*', async (c) => {
  // 保持原始请求结构
  const newRequest = new Request(c.req.raw)
  return await c.env.MY_CONTAINER.fetch(newRequest)
})

export default {
  fetch: app.fetch
}
