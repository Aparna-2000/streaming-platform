// Path: backend/src/middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt, { VerifyOptions } from 'jsonwebtoken';
import { pool } from '../config/database';

export interface AuthRequest extends Request {
  user?: {
    sub: string;
    role?: string | null;
    username?: string;
    email?: string;
  };
}

export const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
  // JWT-based auth (stateless). No server-side session checks.
  try {
    // Prefer Authorization: Bearer <token>, fall back to cookies
    const authHeader = req.headers.authorization;
    const bearerToken = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : undefined;
    const cookieToken = (req as any).cookies?.accessToken || (req as any).cookies?.token;
    const token = bearerToken || cookieToken;

    if (!token) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }

    const secret =
      process.env.JWT_ACCESS_SECRET ||
      process.env.JWT_SECRET ||
      'fallback-secret';

    const verifyOpts: VerifyOptions = {};
    if (process.env.JWT_ISSUER) verifyOpts.issuer = process.env.JWT_ISSUER;
    if (process.env.JWT_AUDIENCE) verifyOpts.audience = process.env.JWT_AUDIENCE;

    const decoded = jwt.verify(token, secret, verifyOpts) as any;

    // Support either { userId } or JWT standard { sub }
    const userIdRaw = decoded.userId ?? decoded.sub ?? decoded.id;
    const userId = Number(userIdRaw);
    if (!userId || Number.isNaN(userId)) {
      return res.status(401).json({ success: false, message: 'Invalid token payload' });
    }

    // Verify user still exists
    const [rows] = await pool.execute('SELECT id, username, email, role FROM users WHERE id = ?', [userId]);

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    // Attach user to request for downstream handlers
    const user = rows[0] as { id: number; username: string; email: string; role?: string };
    req.user = {
      sub: String(user.id),
      role: user.role || null,
      username: user.username,
      email: user.email
    };

    return next();
  } catch (error) {
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};
