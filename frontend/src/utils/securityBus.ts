// Broadcast to all tabs on same origin
const channel = new BroadcastChannel('security_channel');

export function publishSecurityAlert(payload: any) {
  channel.postMessage(payload);
}

export function subscribeSecurityAlert(handler: (payload: any) => void) {
  channel.addEventListener('message', (e) => handler(e.data));
  return () => channel.close();
}
