import { Router, Request, Response } from 'express';
import { addClient } from '../realtime/securityEvents';
import { verifyRefreshToken } from '../utils/refreshTokens';

const router: Router = Router();

/**
 * GET /security/stream
 * SSE stream for security alerts (per authenticated user)
 * Uses query parameter-based authentication since EventSource doesn't support custom headers
 */
router.get('/stream', async (req: Request, res: Response) => {
  try {
    // Get access token from query parameter since EventSource doesn't support custom headers
    const accessToken = req.query.token as string;
    
    if (!accessToken) {
      return res.status(401).json({ success: false, message: 'No access token provided' });
    }

    // Verify the access token using JWT
    const jwt = require('jsonwebtoken');
    const secret = process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET || 'fallback-secret';
    
    let decoded: any;
    try {
      decoded = jwt.verify(accessToken, secret);
    } catch (jwtError) {
      return res.status(401).json({ success: false, message: 'Invalid access token' });
    }

    const userId = decoded.sub || decoded.id;
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Invalid token payload' });
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

    addClient(parseInt(userId), res);
    
  } catch (error) {
    console.error('SSE authentication error:', error);
    return res.status(401).json({ success: false, message: 'Authentication failed' });
  }
});

export default router;
