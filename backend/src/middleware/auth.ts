// Path: backend/src/middleware/auth.ts
import jwt, { VerifyOptions } from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { pool } from '../config/database';
import { RowDataPacket } from 'mysql2';
import { emitSecurityEvent } from '../realtime/securityEvents';

// Define the structure of the user object in the request
export interface AuthRequest extends Request {
  user?: {
    sub: string;
    role?: string | null;
    username?: string;
    email?: string;
    device_info?: string;
    ip_address?: string;
  };
}

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';

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

    // Get current request info for device binding validation
    const currentDeviceInfo = req.headers['user-agent'] || 'Unknown';
    const currentIpAddress = req.ip || req.connection.remoteAddress || 'Unknown';

    // Fetch user from database with device binding info from latest refresh token
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT u.id, u.username, u.email, u.role, 
              rt.device_info, rt.ip_address
       FROM users u 
       LEFT JOIN refresh_tokens rt ON u.id = rt.user_id 
       WHERE u.id = ? AND rt.revoked_at IS NULL
       ORDER BY rt.created_at DESC 
       LIMIT 1`,
      [userId]
    );

    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'User not found or no active session' });
    }

    const user = rows[0];
    
    // Debug logging
    console.log(`🔍 Debug - User validation:
      User ID: ${user.id}
      Device Info: ${user.device_info || 'NULL'}
      IP Address: ${user.ip_address || 'NULL'}
      Current Device: ${currentDeviceInfo}
      Current IP: ${currentIpAddress}`);

    // Enhanced security: Validate device binding for access tokens
    if (user.device_info && user.ip_address) {
      console.log('🔍 Device/IP validation triggered');
      const deviceMismatch = user.device_info !== currentDeviceInfo;
      const ipMismatch = user.ip_address !== currentIpAddress;

      if (deviceMismatch || ipMismatch) {
        console.log(`🔍 Mismatch detected - Device: ${deviceMismatch}, IP: ${ipMismatch}`);
        console.warn(`🚨 Suspicious token usage detected:
          User ID: ${user.id}
          Original Device: ${user.device_info}
          Current Device: ${currentDeviceInfo}
          Original IP: ${user.ip_address}
          Current IP: ${currentIpAddress}
          Device Match: ${!deviceMismatch}
          IP Match: ${!ipMismatch}`);

        // SECURITY BREACH: Immediately revoke all user sessions
        try {
          await pool.execute(
            'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
            [user.id]
          );
          console.error(`🚨 SECURITY ALERT: All sessions revoked for user ${user.id} due to suspicious activity`);
          // NEW: push event to all connected sessions for this user
          emitSecurityEvent(user.id, {
            type: 'SECURITY_ALERT',
            reason: 'DEVICE_OR_IP_MISMATCH',
            action: 'FORCE_LOGOUT',
            ts: Date.now()
          });
        } catch (error) {
          console.error('Failed to revoke sessions:', error);
        }

        // Enhanced security: Block tokens from different devices/IPs
        return res.status(403).json({ 
          success: false, 
          message: 'Security breach detected. All sessions have been terminated for your protection.',
          securityAlert: true,
          action: 'FORCE_LOGOUT'
        });
      } else {
        console.log('🔍 Device/IP validation passed');
      }
    } else {
      console.log('🔍 Device/IP validation skipped (missing device or IP info)');
    }

    // Attach user info to request
    req.user = {
      sub: String(user.id),
      role: user.role,
      username: user.username,
      email: user.email,
      device_info: user.device_info,
      ip_address: user.ip_address
    };

    return next();
  } catch (error) {
    console.error('Token verification failed:', error);
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};
