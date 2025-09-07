import { Response } from 'express';

type Client = { userId: number; res: Response };
const clients = new Map<number, Set<Response>>();

export function addClient(userId: number, res: Response) {
  if (!clients.has(userId)) clients.set(userId, new Set());
  clients.get(userId)!.add(res);

  // Remove on close
  reqOnClose(res, () => {
    clients.get(userId)?.delete(res);
    if (clients.get(userId)?.size === 0) clients.delete(userId);
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
  if (!bucket) return;
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of bucket) {
    try {
      res.write(data);
    } catch (_) {
      // if write fails, drop the client
      bucket.delete(res);
    }
  }
}
