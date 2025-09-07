import { Router, Request, Response } from 'express';
import { authenticateToken, AuthRequest } from '../middleware/auth';
import { addClient } from '../realtime/securityEvents';
import { verifyAccessToken } from '../utils/jwt';

const router: Router = Router();

/**
 * GET /security/stream?token=<access_token>
 * SSE stream for security alerts (per authenticated user)
 * Uses query parameter for authentication since EventSource doesn't support custom headers
 */
router.get('/stream', (req: Request, res: Response) => {
  try {
    // Get token from query parameter since EventSource doesn't support custom headers
    const token = req.query.token as string;
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    // Verify the token using the same utility as other parts of the app
    const decoded = verifyAccessToken(token);
    
    if (!decoded.sub) {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }

    // SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // for nginx
    res.setHeader('Access-Control-Allow-Origin', process.env.FRONTEND_URL || 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    res.flushHeaders?.();

    // Initial hello
    res.write(`event: ping\ndata: "connected"\n\n`);

    addClient(Number(decoded.sub), res);
    
  } catch (error) {
    console.error('SSE authentication error:', error);
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
});

export default router;
