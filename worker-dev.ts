import { Container } from "@cloudflare/containers";

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request: Request): Promise<Response> {
  // 处理请求的逻辑
  return new Response("Hello from Cloudflare Worker!", {
    headers: { "content-type": "text/plain" },
  });
}
