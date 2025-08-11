env.SZ_CONTAINER.fetch(request)
export class SZContainer extends Container {
  defaultPort = 80; // Port the container is listening on
  sleepAfter = "1m"; // Stop the instance if requests not sent for 1 minutes
}

const INSTANCE_COUNT = 12;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
  return await this.containerFetch(request, 80);
  },
};
