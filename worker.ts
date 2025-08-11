try {
          import { Container, getRandom } from "@cloudflare/containers";

            // Use containers here
        } catch (error) {
            console.warn("Could not load @cloudflare/containers:", error);
            // Handle the case where containers are not available
        }
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
