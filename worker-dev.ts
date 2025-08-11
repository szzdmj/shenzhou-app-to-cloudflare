export class SZContainer extends Container {
  defaultPort = 80;
  sleepAfter = '3s';
  envVars = {
    MESSAGE: 'I was passed in via the container class!',
  };

  override onStart() {
    console.log('Container successfully started');
  }

  override onStop() {
    console.log('Container successfully shut down');
  }

  override onError(error: unknown) {
    console.log('Container error:', error);
  }
}
