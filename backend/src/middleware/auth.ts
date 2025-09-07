// Path: backend/src/middleware/auth.ts
import jwt, { VerifyOptions } from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { pool } from '../config/database';
import { RowDataPacket } from 'mysql2';
import { emitSecurityEvent } from '../realtime/securityEvents';
import { generateDeviceFingerprint } from '../utils/deviceFingerprint';

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

    let decoded: any;
    try {
      decoded = jwt.verify(token, secret, verifyOpts);
    } catch (jwtError: any) {
      console.log('🚨 JWT VERIFICATION FAILED:', jwtError.message);
      
      // Check if this is a token theft attempt (valid format but wrong signature/expired)
      if (jwtError.name === 'JsonWebTokenError' || jwtError.name === 'TokenExpiredError') {
        console.log('🚨 POTENTIAL TOKEN THEFT - Invalid/expired token used');
        
        // Try to decode without verification to get user info for security alert
        try {
          const unverifiedPayload = jwt.decode(token) as any;
          const suspiciousUserId = unverifiedPayload?.userId ?? unverifiedPayload?.sub ?? unverifiedPayload?.id;
          
          if (suspiciousUserId) {
            console.log(`🚨 Suspicious token activity for user ID: ${suspiciousUserId}`);
            
            // Revoke all sessions for this user as a security measure
            await pool.execute(
              'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
              [suspiciousUserId]
            );
            
            // Emit security event
            emitSecurityEvent(suspiciousUserId, {
              type: 'SECURITY_ALERT',
              reason: 'INVALID_TOKEN_USAGE',
              message: 'Invalid or expired token detected - potential theft attempt',
              tokenError: jwtError.message,
              timestamp: new Date().toISOString()
            });
          }
        } catch (decodeError) {
          console.log('🚨 Could not decode suspicious token for security analysis');
        }
        
        return res.status(403).json({
          success: false,
          message: 'Invalid or expired token detected',
          securityAlert: true,
          action: 'FORCE_LOGOUT',
          details: {
            reason: 'INVALID_TOKEN_USAGE',
            error: jwtError.message
          }
        });
      }
      
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }

    // Support either { userId } or JWT standard { sub }
    const userIdRaw = decoded.userId ?? decoded.sub ?? decoded.id;
    const userId = Number(userIdRaw);
    if (!userId || Number.isNaN(userId)) {
      return res.status(401).json({ success: false, message: 'Invalid token payload' });
    }

    // Get current request info for device binding validation
    const currentDeviceFingerprint = generateDeviceFingerprint(req);
    const currentIpAddress = req.ip || req.connection.remoteAddress || 'Unknown';

    // Check for duplicate token usage - same token from multiple IPs/devices simultaneously
    const tokenHash = require('crypto').createHash('sha256').update(token).digest('hex');
    const currentTime = new Date();
    
    // Store token usage tracking (in production, use Redis for better performance)
    const [tokenUsageRows] = await pool.execute<RowDataPacket[]>(
      `SELECT COUNT(*) as usage_count, GROUP_CONCAT(DISTINCT ip_address) as ips, 
              GROUP_CONCAT(DISTINCT device_info) as devices
       FROM token_usage_log 
       WHERE token_hash = ? AND created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE)`,
      [tokenHash]
    );
    
    // Log current token usage
    await pool.execute(
      `INSERT INTO token_usage_log (token_hash, user_id, ip_address, device_info, created_at) 
       VALUES (?, ?, ?, ?, NOW()) 
       ON DUPLICATE KEY UPDATE created_at = NOW()`,
      [tokenHash, userId, currentIpAddress, JSON.stringify(currentDeviceFingerprint)]
    );

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
      console.log('🚨 NO ACTIVE SESSION FOUND - Token may be stolen or session revoked');
      
      // Emit security alert for session not found
      emitSecurityEvent(userId, {
        type: 'SECURITY_ALERT',
        reason: 'NO_ACTIVE_SESSION',
        message: 'Token used but no active session found - potential theft',
        timestamp: new Date().toISOString()
      });
      
      return res.status(403).json({
        success: false,
        message: 'No active session found - please login again',
        securityAlert: true,
        action: 'FORCE_LOGOUT',
        details: {
          reason: 'NO_ACTIVE_SESSION'
        }
      });
    }

    const user = rows[0];
    
    // Check for duplicate token usage from multiple locations
    const tokenUsage = tokenUsageRows[0];
    if (tokenUsage && tokenUsage.usage_count > 1) {
      const uniqueIPs = tokenUsage.ips ? tokenUsage.ips.split(',').filter((ip: string, index: number, arr: string[]) => arr.indexOf(ip) === index) : [];
      const uniqueDevices = tokenUsage.devices ? tokenUsage.devices.split(',').filter((device: string, index: number, arr: string[]) => arr.indexOf(device) === index) : [];
      
      if (uniqueIPs.length > 1 || uniqueDevices.length > 1) {
        console.log('🚨 DUPLICATE TOKEN USAGE DETECTED');
        console.log(`      Token used from ${uniqueIPs.length} different IPs: ${uniqueIPs.join(', ')}`);
        console.log(`      Token used from ${uniqueDevices.length} different devices`);
        
        // Revoke all sessions immediately
        await pool.execute(
          'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
          [user.id]
        );
        
        // Emit security event
        emitSecurityEvent(user.id, {
          type: 'SECURITY_ALERT',
          reason: 'DUPLICATE_TOKEN_USAGE',
          message: 'Same token used simultaneously from multiple locations',
          uniqueIPs,
          uniqueDevices: uniqueDevices.length,
          timestamp: new Date().toISOString()
        });
        
        return res.status(403).json({
          success: false,
          message: 'Token theft detected - simultaneous usage from multiple locations',
          securityAlert: true,
          action: 'FORCE_LOGOUT',
          details: {
            reason: 'DUPLICATE_TOKEN_USAGE',
            uniqueIPs,
            deviceCount: uniqueDevices.length
          }
        });
      }
    }
    
    // FORCE STRICT BROWSER SESSION BINDING - Always validate device/IP
    console.log('🔍 Debug - User validation:');
    console.log(`      User ID: ${user.id}`);
    console.log(`      Stored Device Info: ${user.device_info}`);
    console.log(`      Stored IP: ${user.ip_address}`);
    console.log(`      Current Device Fingerprint: ${currentDeviceFingerprint.fingerprint}`);
    console.log(`      Current User-Agent: ${currentDeviceFingerprint.userAgent}`);
    console.log(`      Current IP: ${currentIpAddress}`);
    console.log('🔍 Device/IP validation triggered');
    
    // Compare stored device fingerprint with current
    let deviceMatches = false;
    let ipMatches = false;
    
    if (user.device_info) {
      // Try to parse stored device info as JSON (new format) or use as string (old format)
      try {
        const storedDevice = JSON.parse(user.device_info);
        // New format: compare fingerprints
        if (storedDevice.fingerprint) {
          deviceMatches = storedDevice.fingerprint === currentDeviceFingerprint.fingerprint;
          console.log(`      Stored fingerprint: ${storedDevice.fingerprint}`);
          console.log(`      Current fingerprint: ${currentDeviceFingerprint.fingerprint}`);
        } else {
          // Fallback: compare user agents
          deviceMatches = storedDevice.userAgent === currentDeviceFingerprint.userAgent;
          console.log(`      Stored User-Agent (JSON): ${storedDevice.userAgent}`);
          console.log(`      Current User-Agent: ${currentDeviceFingerprint.userAgent}`);
        }
      } catch {
        // Old format: simple User-Agent string comparison
        deviceMatches = user.device_info === currentDeviceFingerprint.userAgent;
        console.log(`      Using User-Agent comparison (old format)`);
        console.log(`      Stored User-Agent: ${user.device_info}`);
        console.log(`      Current User-Agent: ${currentDeviceFingerprint.userAgent}`);
      }
    }
    
    if (user.ip_address) {
      ipMatches = user.ip_address === currentIpAddress;
    }

    console.log('🔍 VALIDATION RESULTS:');
    console.log(`      Device Match: ${deviceMatches}`);
    console.log(`      IP Match: ${ipMatches}`);
    console.log(`      Has stored device: ${!!user.device_info}`);
    console.log(`      Has stored IP: ${!!user.ip_address}`);

    // TEMPORARY: FORCE CROSS-BROWSER DETECTION FOR TESTING
    // This will always trigger security alerts to test the frontend
    const shouldBlock = true; // Force blocking for testing
    console.log('🧪 FORCING SECURITY BLOCK FOR TESTING - ALL REQUESTS WILL BE BLOCKED');
    
    console.log(`🔍 SHOULD BLOCK: ${shouldBlock} (FORCED FOR TESTING)`);
    
    if (shouldBlock) {
      console.log('🚨 BLOCKING ACCESS - FORCED CROSS-BROWSER DETECTION TEST');
      
      // IMMEDIATE session revocation for security breach
      await pool.execute(
        'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
        [user.id]
      );
      
      console.log('🚨 ALL USER SESSIONS REVOKED due to cross-browser/cross-IP access');
      
      // Emit security event to all connected sessions for this user
      emitSecurityEvent(user.id, {
        type: 'SECURITY_ALERT',
        reason: 'CROSS_BROWSER_IP_VIOLATION',
        message: 'Token usage from different browser/IP detected',
        expectedDevice: user.device_info,
        actualDevice: JSON.stringify(currentDeviceFingerprint),
        expectedIP: user.ip_address,
        actualIP: currentIpAddress,
        timestamp: new Date().toISOString()
      });
      
      return res.status(403).json({
        success: false,
        message: 'Access denied: Token usage from different browser/IP detected',
        securityAlert: true,
        action: 'FORCE_LOGOUT',
        details: {
          reason: 'CROSS_BROWSER_IP_VIOLATION',
          expectedDevice: user.device_info,
          actualDevice: JSON.stringify(currentDeviceFingerprint),
          expectedIP: user.ip_address,
          actualIP: currentIpAddress
        }
      });
    } else {
      console.log('🔍 Device/IP validation passed');
    }

    // Attach user info to request
    req.user = {
      sub: String(user.id),
      username: user.username,
      email: user.email,
      role: user.role,
    };

    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ success: false, message: 'Authentication error' });
  }
};
