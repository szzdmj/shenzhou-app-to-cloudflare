import { Container, getRandom } from "@cloudflare/containers";

export class SZContainer extends Container {
  defaultPort = 80; // Port the container is listening on
  sleepAfter = "1m"; // Stop the instance if requests not sent for 1 minutes
}

const INSTANCE_COUNT = 12;

export default {
    // note: "getRandom" to be replaced with latency-aware routing in the near future
    const containerInstance = getRandom(env.BACKEND, INSTANCE_COUNT);
    return containerInstance.fetch(request);
  },
};
