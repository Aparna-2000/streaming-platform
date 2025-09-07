import crypto from 'crypto';
import { pool } from '../config/database';
import { OkPacket, RowDataPacket } from 'mysql2';
import { DeviceFingerprint } from './deviceFingerprint';
import { AuthRequest } from '../middleware/auth';

interface RefreshTokenRow extends RowDataPacket {
  id: number;
  user_id: number;
  token_hash: string;
  expires_at: Date;
  created_at: Date;
  revoked_at: Date | null;
  device_info: string | null;
  ip_address: string | null;
  device_fingerprint: string | null;
}

interface User {
  id: number;
  username: string;
  email: string;
  role: string;
}

interface VerifyTokenResult {
  valid: boolean;
  user?: User;
  reason?: string;
}

/**
 * Generate a secure random refresh token
 */
export function generateRefreshToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Hash a refresh token for database storage
 */
export function hashRefreshToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Store refresh token in database
 */
export async function storeRefreshToken(
  userId: number,
  token: string,
  expiresAt: Date,
  deviceInfo: string,
  ipAddress: string,
  deviceFingerprint?: DeviceFingerprint
): Promise<number> {
  const tokenHash = hashRefreshToken(token);
  
  const [result] = await pool.execute<OkPacket>(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, device_info, ip_address, device_fingerprint) 
     VALUES (?, ?, ?, ?, ?, ?)`,
    [userId, tokenHash, expiresAt, deviceInfo, ipAddress, deviceFingerprint ? JSON.stringify(deviceFingerprint) : null]
  );
  
  return result.insertId;
}

/**
 * Verify and retrieve refresh token from database with enhanced validation
 */
export async function verifyRefreshToken(token: string, req?: any): Promise<{
  valid: boolean;
  user?: { id: number; username: string; email: string; role: string };
  reason?: string;
} | null> {
  try {
    const tokenHash = hashRefreshToken(token);
    
    const [rows] = await pool.execute<RefreshTokenRow[]>(
      `SELECT rt.*, u.username, u.email, u.role 
       FROM refresh_tokens rt 
       JOIN users u ON rt.user_id = u.id
       WHERE rt.token_hash = ? AND rt.expires_at > NOW() AND rt.revoked_at IS NULL 
       LIMIT 1`,
      [tokenHash]
    );
    
    if (rows.length === 0) {
      return { valid: false, reason: 'Token not found or expired' };
    }
    
    const tokenData = rows[0] as RefreshTokenRow & { username: string; email: string; role: string };
    
    // Enhanced validation if request context provided
    if (req) {
      const currentDevice = req.headers['user-agent'] || 'Unknown';
      const currentIP = req.ip || req.connection.remoteAddress || 'Unknown';
      
      // Device validation
      if (tokenData.device_info && tokenData.device_info !== currentDevice) {
        console.log(`🚨 Device mismatch: stored=${tokenData.device_info}, current=${currentDevice}`);
        // For security, revoke the token and reject
        await revokeRefreshToken(token);
        return { valid: false, reason: 'Device validation failed' };
      }
      
      // IP validation
      if (tokenData.ip_address && tokenData.ip_address !== currentIP) {
        console.log(`🚨 IP mismatch: stored=${tokenData.ip_address}, current=${currentIP}`);
        // For security, revoke the token and reject
        await revokeRefreshToken(token);
        return { valid: false, reason: 'IP validation failed' };
      }
    }
    
    return {
      valid: true,
      user: {
        id: tokenData.user_id,
        username: tokenData.username,
        email: tokenData.email,
        role: tokenData.role
      }
    };
  } catch (error) {
    console.error('Error verifying refresh token:', error);
    return null;
  }
}

/**
 * Revoke a specific refresh token
 */
export async function revokeRefreshToken(token: string): Promise<boolean> {
  const tokenHash = hashRefreshToken(token);
  
  const [result] = await pool.execute<OkPacket>(
    `UPDATE refresh_tokens SET revoked_at = NOW() 
     WHERE token_hash = ? AND revoked_at IS NULL`,
    [tokenHash]
  );
  
  return result.affectedRows > 0;
}

/**
 * Revoke all refresh tokens for a user (logout from all devices)
 */
export async function revokeAllUserTokens(userId: number): Promise<number> {
  const [result] = await pool.execute<OkPacket>(
    `UPDATE refresh_tokens SET revoked_at = NOW() 
     WHERE user_id = ? AND revoked_at IS NULL`,
    [userId]
  );
  
  return result.affectedRows;
}

/**
 * Clean up expired tokens (run periodically)
 */
export async function cleanupExpiredTokens(): Promise<number> {
  const [result] = await pool.execute<OkPacket>(
    `DELETE FROM refresh_tokens 
     WHERE expires_at < NOW() OR revoked_at < DATE_SUB(NOW(), INTERVAL 1 DAY)`,
    []
  );
  
  return result.affectedRows;
}

/**
 * Get active token count for a user
 */
export async function getUserActiveTokenCount(userId: number): Promise<number> {
  const [rows] = await pool.execute<RowDataPacket[]>(
    `SELECT COUNT(*) as count FROM refresh_tokens 
     WHERE user_id = ? AND expires_at > NOW() AND revoked_at IS NULL`,
    [userId]
  );
  
  return rows[0].count;
}

async function getUserById(userId: number): Promise<User> {
  const [rows] = await pool.execute<RowDataPacket[]>(
    `SELECT * FROM users WHERE id = ? LIMIT 1`,
    [userId]
  );
  
  return rows[0] as User;
}

function deviceFingerprintMatches(storedFingerprint: string, providedFingerprint: DeviceFingerprint): boolean {
  const storedFingerprintObject = JSON.parse(storedFingerprint);
  
  return JSON.stringify(storedFingerprintObject) === JSON.stringify(providedFingerprint);
}
