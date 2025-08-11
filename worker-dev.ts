class MyBackend extends Container {
  defaultPort = 80;
  autoscale = true; // global autoscaling on - new instances spin up when memory or CPU utilization is high
}

// routes requests to the nearest ready container and load balance globally
async fetch(request, env) {
  return getContainer(env.MY_BACKEND).fetch(request);
}
