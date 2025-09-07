import { Response } from 'express';
import bcrypt from 'bcrypt';
import { pool } from '../config/database';
import { AuthRequest } from '../middleware/auth';
import { revokeAllUserTokens } from '../utils/refreshTokens';
import { emitSecurityEvent } from '../realtime/securityEvents';
import { generateDeviceFingerprint } from '../utils/deviceFingerprint';

/**
 * POST /auth/enforce-single-session
 * Revokes all existing sessions before login (single session enforcement)
 * Now includes cross-browser login detection and security alerts
 */
export const enforceSingleSession = async (userId: number, req?: any) => {
  try {
    // Check if user has existing active sessions
    const [existingSessions] = await pool.execute(
      `SELECT COUNT(*) as session_count, 
              GROUP_CONCAT(DISTINCT device_info) as devices,
              GROUP_CONCAT(DISTINCT ip_address) as ips
       FROM refresh_tokens 
       WHERE user_id = ? AND revoked_at IS NULL`,
      [userId]
    );

    const sessionData = (existingSessions as any[])[0];
    const hasActiveSessions = sessionData.session_count > 0;

    if (hasActiveSessions && req) {
      // Get current login attempt details
      const currentDevice = generateDeviceFingerprint(req);
      const currentIP = req.ip || req.connection.remoteAddress || 'Unknown';
      const currentUserAgent = req.headers['user-agent'] || 'Unknown';

      // Check if this is a cross-browser login attempt
      const existingDevices = sessionData.devices ? sessionData.devices.split(',') : [];
      const existingIPs = sessionData.ips ? sessionData.ips.split(',') : [];

      const isCrossBrowserLogin = !existingDevices.some((device: string) => 
        device.includes(currentUserAgent.split('/')[0]) // Compare browser type
      );

      const isCrossIPLogin = !existingIPs.includes(currentIP);

      if (isCrossBrowserLogin || isCrossIPLogin) {
        console.log('🚨 CROSS-BROWSER/IP LOGIN DETECTED');
        console.log(`      User ID: ${userId}`);
        console.log(`      Existing devices: ${existingDevices.join(', ')}`);
        console.log(`      New device: ${currentUserAgent}`);
        console.log(`      Existing IPs: ${existingIPs.join(', ')}`);
        console.log(`      New IP: ${currentIP}`);

        // Emit security alert to all existing sessions BEFORE revoking them
        emitSecurityEvent(userId, {
          type: 'SECURITY_ALERT',
          reason: 'CROSS_BROWSER_LOGIN_ATTEMPT',
          message: 'New login detected from different browser/IP - all sessions will be terminated',
          existingDevices,
          newDevice: currentUserAgent,
          existingIPs,
          newIP: currentIP,
          timestamp: new Date().toISOString()
        });

        // Give existing sessions a moment to receive the alert before revoking
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    // Revoke all existing refresh tokens for this user
    await revokeAllUserTokens(userId);
    console.log(`🔒 Single session enforced: All previous sessions revoked for user ${userId}`);
    
    if (hasActiveSessions) {
      console.log(`🔒 ${sessionData.session_count} existing session(s) terminated`);
    }
  } catch (error) {
    console.error('Failed to enforce single session:', error);
    throw error;
  }
};

/**
 * POST /auth/verify-password
 * Additional authentication for sensitive operations
 */
export const verifyPasswordForSensitiveOp = async (req: AuthRequest, res: Response) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password verification required for this operation' 
      });
    }

    if (!req.user?.sub) {
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    // Get user's current password hash
    const [rows] = await pool.execute(
      'SELECT password_hash FROM users WHERE id = ? LIMIT 1',
      [req.user.sub]
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = rows[0] as { password_hash: string };

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid password. Please verify your current password.' 
      });
    }

    return res.json({
      success: true,
      message: 'Password verified successfully',
      data: { verified: true }
    });

  } catch (error) {
    console.error('Password verification error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'An error occurred during password verification' 
    });
  }
};

/**
 * POST /auth/change-email
 * Change email with additional password verification
 */
export const changeEmail = async (req: AuthRequest, res: Response) => {
  try {
    const { newEmail, currentPassword } = req.body;

    if (!newEmail || !currentPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'New email and current password are required' 
      });
    }

    if (!req.user?.sub) {
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    // Verify current password first
    const [userRows] = await pool.execute(
      'SELECT password_hash FROM users WHERE id = ? LIMIT 1',
      [req.user.sub]
    );

    if (!Array.isArray(userRows) || userRows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = userRows[0] as { password_hash: string };
    const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
    
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Current password is incorrect' 
      });
    }

    // Check if email already exists
    const [existingEmail] = await pool.execute(
      'SELECT id FROM users WHERE email = ? AND id != ?',
      [newEmail, req.user.sub]
    );

    if (Array.isArray(existingEmail) && existingEmail.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email address is already in use' 
      });
    }

    // Update email
    await pool.execute(
      'UPDATE users SET email = ? WHERE id = ?',
      [newEmail, req.user.sub]
    );

    // Revoke all sessions for security (force re-login)
    await revokeAllUserTokens(Number(req.user.sub));

    return res.json({
      success: true,
      message: 'Email updated successfully. Please log in again for security.',
      data: { forceLogout: true }
    });

  } catch (error) {
    console.error('Change email error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'An error occurred while updating email' 
    });
  }
};

/**
 * POST /auth/change-password
 * Change password with additional verification
 */
export const changePassword = async (req: AuthRequest, res: Response) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Current password and new password are required' 
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: 'New password must be at least 8 characters long' 
      });
    }

    if (!req.user?.sub) {
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    // Verify current password
    const [userRows] = await pool.execute(
      'SELECT password_hash FROM users WHERE id = ? LIMIT 1',
      [req.user.sub]
    );

    if (!Array.isArray(userRows) || userRows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = userRows[0] as { password_hash: string };
    const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
    
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Current password is incorrect' 
      });
    }

    // Hash new password
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    await pool.execute(
      'UPDATE users SET password_hash = ? WHERE id = ?',
      [newPasswordHash, req.user.sub]
    );

    // Revoke all sessions for security (force re-login)
    await revokeAllUserTokens(Number(req.user.sub));

    return res.json({
      success: true,
      message: 'Password updated successfully. Please log in again for security.',
      data: { forceLogout: true }
    });

  } catch (error) {
    console.error('Change password error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'An error occurred while updating password' 
    });
  }
};
