import { Hono } from 'hono'

// 👇 导入你的容器类（如果在其他文件里）
import { MyContainer } from './my-container' // 确保路径正确

type Env = {
  MY_CONTAINER: Fetcher
}

const app = new Hono<{ Bindings: Env }>()

// Health check
app.get('/health', (c) => c.text('OK'))

// Forward all unmatched requests to the container
app.all('*', async (c) => {
  const newRequest = new Request(c.req.raw, {
    headers: c.req.raw.headers,
  })
  return await c.env.MY_CONTAINER.fetch(newRequest)
})

export default app

// ✅ 必须导出容器类
export { MyContainer }
