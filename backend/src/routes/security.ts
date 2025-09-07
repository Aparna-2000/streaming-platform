import { Router, Request, Response } from 'express';
import { authenticateToken, AuthRequest } from '../middleware/auth';
import { addClient } from '../realtime/securityEvents';

const router: Router = Router();

/**
 * GET /security/stream
 * SSE stream for security alerts (per authenticated user)
 */
router.get('/stream', authenticateToken, (req: AuthRequest, res: Response) => {
  if (!req.user?.sub) return res.status(401).end();

  // SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // for nginx

  res.flushHeaders?.();

  // Initial hello
  res.write(`event: ping\ndata: "connected"\n\n`);

  addClient(Number(req.user.sub), res);
});

export default router;
