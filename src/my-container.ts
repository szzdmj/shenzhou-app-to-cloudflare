export class MyContainer {
  async fetch(request: Request): Promise<Response> {
    return new Response("Hello from MyContainer Durable Object!", {
      status: 200,
      headers: {
        "Content-Type": "text/plain"
      }
    })
  }
}