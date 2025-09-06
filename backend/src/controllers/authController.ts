import { Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { validationResult } from 'express-validator';
import { pool } from '../config/database';
import { AuthRequest } from '../middleware/auth';
import { OkPacket } from 'mysql2';
import { signAccessToken } from '../utils/jwt';
import { 
  generateRefreshToken, 
  storeRefreshToken, 
  verifyRefreshToken, 
  revokeRefreshToken,
  revokeAllUserTokens 
} from '../utils/refreshTokens';

// Refresh-token config (access token handled by signAccessToken -> 15m by default)
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'fallback-refresh-secret';
const REFRESH_TOKEN_EXPIRY = '7d';

/**
 * POST /auth/login
 * Body: { username: string, password: string }
 * - Verifies user credentials
 * - Issues short-lived access token (~15m via signAccessToken)
 * - Issues long-lived refresh token (7d) in HttpOnly cookie
 * - Optionally sets access token cookie (HttpOnly) for same-site usage
 */
export const login = async (req: AuthRequest, res: Response) => {
  console.log(' Login controller called');
  console.log(' Received body:', req.body);
  console.log('Login attempt:', req.body.username); // Debug log
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Validation errors:', errors.array()); // Debug log
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid input', 
        errors: errors.array() 
      });
    }

    const { username, password } = req.body as { username?: string; password?: string };
    
    // Validate and sanitize inputs
    if (!username || !password) {
      console.log(' Missing username or password');
      return res.status(400).json({ 
        success: false, 
        message: 'Username and password are required' 
      });
    }

    // Check for invalid characters first (before length validation)
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.log(' Username invalid characters:', username);
      return res.status(400).json({ 
        success: false, 
        message: 'Username can only contain letters, numbers, underscores, hyphens and should not extend 30 characters' 
      });
    }

    // Then check length constraints
    if (username.length < 3) {
      console.log(' Username too short:', username.length);
      return res.status(400).json({ 
        success: false, 
        message: 'Username must be at least 3 characters' 
      });
    }

    if (username.length > 30) {
      console.log(' Username too long:', username.length);
      return res.status(400).json({ 
        success: false, 
        message: 'Username must be no more than 30 characters' 
      });
    }

    if (password.length < 6) {
      console.log(' Password too short:', password.length);
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters' 
      });
    }

    console.log(' Validation passed, processing login for user:', username); // Debug log

    console.log('Processing login for user:', username); // Debug log

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

    // Generate tokens
    // Access token (~15m) via util (adds issuer/audience if configured)
    const accessToken = signAccessToken({ 
      sub: String(user.id),
      role: user.role 
    });

    // Refresh token (7d) signed with dedicated secret
    const refreshToken = jwt.sign(
      { userId: user.id, username: user.username, tokenType: 'refresh' },
      REFRESH_SECRET,
      { expiresIn: REFRESH_TOKEN_EXPIRY }
    );

    // HttpOnly cookies (keep for your front-end flow)
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });

    // Optional: set access token as HttpOnly cookie (aligns with your middleware that reads cookies)
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000, // 15 minutes
      path: '/',
    });

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        accessToken, // also return for clients that store it elsewhere
        tokenType: 'Bearer',
        expiresIn: 15 * 60, // seconds
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'An error occurred during login' });
  }
};

/**
 * POST /auth/refresh-token
 * - Verifies refresh token from HttpOnly cookie
 * - Issues a new short-lived access token
 */
export const refreshToken = async (req: AuthRequest, res: Response) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ success: false, message: 'No refresh token provided' });
  }

  try {
    // Verify refresh token from database
    const tokenData = await verifyRefreshToken(refreshToken);
    
    if (!tokenData) {
      return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
    }

    // Ensure the user still exists
    const [userRows] = await pool.execute(
      'SELECT id, username, email, role FROM users WHERE id = ? LIMIT 1',
      [tokenData.user_id]
    );

    if (!Array.isArray(userRows) || userRows.length === 0) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    const user = userRows[0] as { id: number; username: string; email: string; role: string };

    // Generate new access token (~15m)
    const newAccessToken = signAccessToken({ 
      sub: String(user.id),
      role: user.role 
    });

    // Update access-token cookie (optional)
    res.cookie('token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000, // 15 minutes
      path: '/',
    });

    return res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken: newAccessToken,
        tokenType: 'Bearer',
        expiresIn: 15 * 60, // 15 minutes in seconds
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      },
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.clearCookie('refreshToken');
    res.clearCookie('token');
    return res.status(403).json({ success: false, message: 'Invalid or expired refresh token' });
  }
};

/**
 * POST /auth/logout
 * - Clears auth cookies
 */
export const logout = (_req: AuthRequest, res: Response) => {
  // Stateless JWTs: no server-side session to destroy
  res.clearCookie('token');
  res.clearCookie('refreshToken');
  // If you previously used session cookies:
  res.clearCookie('sid');
  return res.status(200).json({ success: true, message: 'Logged out successfully' });
};

/**
 * GET /auth/me
 * - Returns the user attached by authenticateToken middleware
 */
export const getCurrentUser = (req: AuthRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }

  return res.json({
    success: true,
    user: {
      id: req.user.sub,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role
    },
  });
};

/**
 * POST /auth/register
 * Body: { username, email, password }
 * - Creates user
 * - Issues access token (~15m) and sets refresh token cookie (7d)
 */
export const register = async (req: AuthRequest, res: Response) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(400)
        .json({ success: false, message: 'Invalid input', errors: errors.array() });
    }

    const { username, email, password } = req.body as {
      username?: string;
      email?: string;
      password?: string;
    };

    // Validate and sanitize inputs
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username, email, and password are required' 
      });
    }

    // Check if user or email already exists
    const [existingUsers] = await pool.execute(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (Array.isArray(existingUsers) && existingUsers.length > 0) {
      return res.status(400).json({ success: false, message: 'Username or email already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const password_hash = await bcrypt.hash(password ?? '', saltRounds);

    // Insert new user
    const [result] = await pool.execute<OkPacket>(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      [username, email, password_hash, 'user'] // Default role is 'user'
    );

    const userId = result.insertId;

    // Issue tokens
    const accessToken = signAccessToken({ sub: String(userId) });

    const refreshToken = jwt.sign(
      { userId, username, tokenType: 'refresh' },
      REFRESH_SECRET,
      { expiresIn: REFRESH_TOKEN_EXPIRY }
    );

    // Set refresh token cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        id: userId,
        username,
        email,
        accessToken, // send access token to client
        tokenType: 'Bearer',
        expiresIn: 15 * 60,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res
      .status(500)
      .json({ success: false, message: 'An error occurred during registration' });
  }
};
