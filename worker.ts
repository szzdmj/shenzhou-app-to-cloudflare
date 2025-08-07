import { Container, getRandom } from "@cloudflare/containers";
const INSTANCE_COUNT = 5;
class Backend extends Container {
  defaultPort = 80;
  sleepAfter = "1m";
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
  let container = await getRandom(env.MY_CONTAINER, INSTANCE_COUNT);
  // Pass the request to the container instance on its default port
  return await container.fetch(request);
  },
};
