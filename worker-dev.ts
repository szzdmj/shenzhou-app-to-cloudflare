import { Container, getRandom } from "@cloudflare/containers";

export class SZContainer extends Container {
  defaultPort = 80; // Port the container is listening on
  sleepAfter = "3m"; // Stop the instance if requests not sent for 3 minutes
}
const INSTANCE_COUNT = 6;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
  let container = await getRandom(env.SZ_CONTAINER, INSTANCE_COUNT);
  // Pass the request to the container instance on its default port
  return await container.fetch(request);
  },
};
