import crypto from 'crypto';
import { pool } from '../config/database';
import { OkPacket, RowDataPacket } from 'mysql2';

interface RefreshTokenRow extends RowDataPacket {
  id: number;
  user_id: number;
  token_hash: string;
  expires_at: Date;
  created_at: Date;
  revoked_at: Date | null;
  device_info: string | null;
  ip_address: string | null;
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
  deviceInfo?: string,
  ipAddress?: string
): Promise<number> {
  const tokenHash = hashRefreshToken(token);
  
  const [result] = await pool.execute<OkPacket>(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, device_info, ip_address) 
     VALUES (?, ?, ?, ?, ?)`,
    [userId, tokenHash, expiresAt, deviceInfo || null, ipAddress || null]
  );
  
  return result.insertId;
}

/**
 * Verify and retrieve refresh token from database
 */
export async function verifyRefreshToken(token: string): Promise<RefreshTokenRow | null> {
  const tokenHash = hashRefreshToken(token);
  
  const [rows] = await pool.execute<RefreshTokenRow[]>(
    `SELECT * FROM refresh_tokens 
     WHERE token_hash = ? AND expires_at > NOW() AND revoked_at IS NULL 
     LIMIT 1`,
    [tokenHash]
  );
  
  return rows.length > 0 ? rows[0] : null;
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
     WHERE expires_at < NOW() OR revoked_at < DATE_SUB(NOW(), INTERVAL 30 DAY)`,
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
