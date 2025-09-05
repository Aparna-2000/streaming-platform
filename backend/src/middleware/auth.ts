import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { pool } from '../config/database';

export interface AuthRequest extends Request {
  user?: {
    id: number;
    username: string;
    email: string;
  };
}

export const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
  // Check if user is already authenticated via session
  if (req.session?.user) {
    req.user = req.session.user;
    return next();
  }

  // Fall back to JWT token
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret') as any;
    
    // Verify user still exists
    const [rows] = await pool.execute(
      'SELECT id, username, email FROM users WHERE id = ?',
      [decoded.userId]
    );
    
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    // Set user in session for future requests
    req.session.user = rows[0] as any;
    req.user = rows[0] as any;
    
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};
