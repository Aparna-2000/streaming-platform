import { Response } from 'express';

type Client = { userId: number; res: Response };
const clients = new Map<number, Set<Response>>();

export function addClient(userId: number, res: Response) {
  if (!clients.has(userId)) clients.set(userId, new Set());
  clients.get(userId)!.add(res);
  
  console.log(`🔗 SSE: Added client for user ${userId}. Total clients for user: ${clients.get(userId)!.size}`);
  console.log(`🔗 SSE: Total users with active connections: ${clients.size}`);

  // Remove on close
  reqOnClose(res, () => {
    clients.get(userId)?.delete(res);
    if (clients.get(userId)?.size === 0) clients.delete(userId);
    console.log(`🔗 SSE: Removed client for user ${userId}`);
  });
}

function reqOnClose(res: Response, cb: () => void) {
  // @ts-ignore - Node types
  res.req.on('close', cb);
  // @ts-ignore
  res.req.on('end', cb);
}

export function emitSecurityEvent(userId: number, payload: any) {
  const bucket = clients.get(userId);
  console.log(`🚨 SSE: Attempting to emit security event to user ${userId}`);
  console.log(`🚨 SSE: Active connections for user: ${bucket?.size || 0}`);
  console.log(`🚨 SSE: Event payload:`, payload);
  
  if (!bucket || bucket.size === 0) {
    console.log(`🚨 SSE: No active connections for user ${userId}`);
    return;
  }

  // Send as both a named event and a data message for better compatibility
  const eventData = `event: SECURITY_ALERT\ndata: ${JSON.stringify(payload)}\n\n`;
  const messageData = `data: ${JSON.stringify(payload)}\n\n`;
  
  let successCount = 0;
  let failCount = 0;
  
  for (const res of bucket) {
    try {
      // Send both formats to ensure compatibility
      res.write(eventData);
      res.write(messageData);
      successCount++;
      console.log(`🚨 SSE: Successfully sent security alert to connection`);
    } catch (error) {
      // if write fails, drop the client
      bucket.delete(res);
      failCount++;
      console.error(`🚨 SSE: Failed to send security alert to connection:`, error);
    }
  }
  
  console.log(`🚨 SSE: Security event sent - Success: ${successCount}, Failed: ${failCount}`);
}
