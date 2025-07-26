import { Hono } from 'hono'

type Env = {
  MY_CONTAINER: Fetcher
}

const app = new Hono<{ Bindings: Env }>()

// Health check
app.get('/health', (c) => c.text('OK'))

// Forward all unmatched requests to the container
app.all('*', async (c) => {
  const url = new URL(c.req.url)
  const newRequest = new Request(c.req.raw, {
    headers: c.req.raw.headers,
  })
  return await c.env.MY_CONTAINER.fetch(newRequest)
})

export default app
