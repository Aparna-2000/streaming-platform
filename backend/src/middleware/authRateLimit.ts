import rateLimit from 'express-rate-limit';

const isDevelopment = process.env.NODE_ENV !== 'production';

// Strict rate limiting for login attempts (brute force protection)
export const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isDevelopment ? 10000 : 5, // Effectively unlimited for development
  message: { 
    success: false, 
    message: 'Too many login attempts, please try again in 15 minutes.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

// Rate limiting for registration (spam protection)
export const registerRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: isDevelopment ? 10000 : 3, // Effectively unlimited for development
  message: { 
    success: false, 
    message: 'Too many registration attempts, please try again in 1 hour.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting for token refresh (prevent token farming)
export const refreshRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isDevelopment ? 10000 : 20, // Effectively unlimited for development
  message: { 
    success: false, 
    message: 'Too many token refresh attempts, please try again later.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting for password operations (sensitive operations)
export const passwordRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: isDevelopment ? 10000 : 3, // Effectively unlimited for development
  message: { 
    success: false, 
    message: 'Too many password change attempts, please try again in 1 hour.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
});
