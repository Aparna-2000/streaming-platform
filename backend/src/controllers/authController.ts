import { Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { validationResult } from 'express-validator';
import { pool } from '../config/database';
import { AuthRequest } from '../middleware/auth';
import { OkPacket } from 'mysql2';
import { signAccessToken } from '../utils/jwt';
import { 
  storeRefreshToken, 
  verifyRefreshToken, 
  revokeRefreshToken
} from '../utils/refreshTokens';
import { generateDeviceFingerprint } from '../utils/deviceFingerprint';
import { enforceSingleSession } from './sessionController';

// Refresh-token config (access token handled by signAccessToken -> 15m by default)
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'fallback-refresh-secret';
const REFRESH_TOKEN_EXPIRY = '30m';

/**
 * POST /auth/login
 * Body: { username: string, password: string }
 * - Verifies user credentials
 * - Issues short-lived access token (~15m via signAccessToken)
 * - Issues long-lived refresh token (30m) in HttpOnly cookie
 * - Optionally sets access token cookie (HttpOnly) for same-site usage
 */
export const login = async (req: AuthRequest, res: Response) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid input', 
        errors: errors.array() 
      });
    }

    const { username, password } = req.body as { username?: string; password?: string };
    
    // Validate and sanitize inputs
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username and password are required' 
      });
    }

    // Check for invalid characters first (before length validation)
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username can only contain letters, numbers, underscores, hyphens and should not extend 30 characters' 
      });
    }

    // Then check length constraints
    if (username.length < 3) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username must be at least 3 characters' 
      });
    }

    if (username.length > 30) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username must be no more than 30 characters' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters' 
      });
    }

    // Get user from database
    const [rows] = await pool.execute(
      'SELECT id, username, email, password_hash, role FROM users WHERE username = ? LIMIT 1',
      [username]
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = rows[0] as {
      id: number;
      username: string;
      email: string;
      password_hash: string;
      role: string;
    };

    // Verify password
    const isValidPassword = await bcrypt.compare(password ?? '', user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Enforce single session (revoke all existing sessions)
    await enforceSingleSession(user.id);

    // Generate device fingerprint for enhanced security
    const deviceFingerprint = generateDeviceFingerprint(req);

    // Generate tokens
    const accessToken = signAccessToken({ 
      sub: String(user.id),
      role: user.role 
    });

    const refreshTokenValue = jwt.sign(
      { user_id: user.id, username: user.username, tokenType: 'refresh' },
      REFRESH_SECRET,
      { expiresIn: REFRESH_TOKEN_EXPIRY }
    );

    // Store refresh token with device/IP binding and fingerprint
    const deviceInfo = req.headers['user-agent'] || 'Unknown';
    const ipAddress = req.ip || req.connection.remoteAddress || 'Unknown';
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

    await storeRefreshToken(user.id, refreshTokenValue, expiresAt, deviceInfo, ipAddress, deviceFingerprint);

    // Set secure cookies
    res.cookie('refreshToken', refreshTokenValue, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 60 * 1000
    });

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      accessToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};

/**
 * POST /auth/refresh-token
 * Validates refresh token and issues new access token
 * Enhanced with device/IP binding validation
 */
export const refreshToken = async (req: AuthRequest, res: Response) => {
  try {
    const refreshTokenValue = req.cookies?.refreshToken;
    
    if (!refreshTokenValue) {
      return res.status(401).json({ 
        success: false, 
        message: 'No refresh token provided' 
      });
    }

    const result = await verifyRefreshToken(refreshTokenValue, req);
    
    if (!result || !result.valid || !result.user) {
      return res.status(401).json({ 
        success: false, 
        message: result?.reason || 'Invalid refresh token' 
      });
    }

    // TypeScript knows result.user exists here due to the check above
    const user = result.user;

    // Generate new access token
    const newAccessToken = signAccessToken({ 
      sub: String(user.id),
      role: user.role 
    });

    return res.status(200).json({
      success: true,
      accessToken: newAccessToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};

/**
 * POST /auth/logout
 * Revokes refresh token and clears cookies
 */
export const logout = async (req: AuthRequest, res: Response) => {
  try {
    const refreshTokenValue = req.cookies?.refreshToken;
    
    if (refreshTokenValue) {
      await revokeRefreshToken(refreshTokenValue);
    }

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * GET /auth/me
 * Returns current user information
 */
export const getCurrentUser = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const userId = req.user.sub;
    const [rows] = await pool.execute(
      'SELECT id, username, email, role FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const user = rows[0] as { id: number; username: string; email: string; role: string };

    return res.status(200).json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

/**
 * POST /auth/register
 * Creates new user account with validation
 */
export const register = async (req: AuthRequest, res: Response) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Invalid input',
        errors: errors.array()
      });
    }

    const { username, email, password } = req.body;

    // Validate inputs
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username, email, and password are required'
      });
    }

    // Check username format
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      return res.status(400).json({
        success: false,
        message: 'Username can only contain letters, numbers, underscores, and hyphens'
      });
    }

    // Check username length
    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({
        success: false,
        message: 'Username must be between 3 and 30 characters'
      });
    }

    // Check password length
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    // Check if user already exists
    const [existingUsers] = await pool.execute(
      'SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1',
      [username, email]
    );

    if (Array.isArray(existingUsers) && existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Username or email already exists'
      });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert new user
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      [username, email, passwordHash, 'user']
    ) as [OkPacket, any];

    const userId = result.insertId;

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: userId,
        username,
        email,
        role: 'user'
      }
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};
