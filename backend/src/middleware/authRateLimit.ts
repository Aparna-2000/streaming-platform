import rateLimit from 'express-rate-limit';

// Strict rate limiting for login attempts (brute force protection)
export const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  message: { 
    success: false, 
    message: 'Too many login attempts, please try again in 15 minutes.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Skip successful requests
  skipSuccessfulRequests: true,
});

// Rate limiting for registration (spam protection)
export const registerRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 registration attempts per hour
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
  max: 20, // limit each IP to 20 refresh attempts per windowMs
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
  max: 3, // limit each IP to 3 password change attempts per hour
  message: { 
    success: false, 
    message: 'Too many password change attempts, please try again in 1 hour.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
});
