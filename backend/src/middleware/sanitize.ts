import { Request, Response, NextFunction } from 'express';
import validator from 'validator';
import xss from 'xss';

/**
 * Sanitizes string input by:
 * 1. Trimming whitespace
 * 2. Escaping HTML entities
 * 3. Filtering XSS attempts
 */
export const sanitizeString = (input: string): string => {
  if (typeof input !== 'string') return '';
  
  // Trim whitespace
  let sanitized = validator.trim(input);
  
  // Escape HTML entities
  sanitized = validator.escape(sanitized);
  
  // Filter XSS attempts
  sanitized = xss(sanitized, {
    whiteList: {}, // No HTML tags allowed
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script']
  });
  
  return sanitized;
};

/**
 * Sanitizes email input
 */
export const sanitizeEmail = (email: string): string => {
  if (typeof email !== 'string') return '';
  
  let sanitized = validator.trim(email.toLowerCase());
  sanitized = validator.normalizeEmail(sanitized) || sanitized;
  
  return sanitized;
};

/**
 * Middleware to sanitize request body fields
 */
export const sanitizeInputs = (fields: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body && typeof req.body === 'object') {
      fields.forEach(field => {
        if (req.body[field] && typeof req.body[field] === 'string') {
          if (field === 'email') {
            req.body[field] = sanitizeEmail(req.body[field]);
          } else if (field === 'password') {
            // Don't sanitize passwords - just trim whitespace
            req.body[field] = validator.trim(req.body[field]);
          } else {
            req.body[field] = sanitizeString(req.body[field]);
          }
        }
      });
    }
    next();
  };
};

/**
 * Validation rules for authentication endpoints
 */
export const authValidationRules = {
  username: {
    minLength: 3,
    maxLength: 30,
    pattern: /^[a-zA-Z0-9_-]+$/ // Only alphanumeric, underscore, hyphen
  },
  email: {
    maxLength: 254
  },
  password: {
    minLength: 6,
    maxLength: 128
  }
};

/**
 * Validates username format and length
 */
export const validateUsername = (username: string): { isValid: boolean; error?: string } => {
  if (!username || typeof username !== 'string') {
    return { isValid: false, error: 'Username is required' };
  }
  
  if (username.length < authValidationRules.username.minLength) {
    return { isValid: false, error: `Username must be at least ${authValidationRules.username.minLength} characters` };
  }
  
  if (username.length > authValidationRules.username.maxLength) {
    return { isValid: false, error: `Username must be no more than ${authValidationRules.username.maxLength} characters` };
  }
  
  if (!authValidationRules.username.pattern.test(username)) {
    return { isValid: false, error: 'Username can only contain letters, numbers, underscores, and hyphens' };
  }
  
  return { isValid: true };
};

/**
 * Validates email format
 */
export const validateEmail = (email: string): { isValid: boolean; error?: string } => {
  if (!email || typeof email !== 'string') {
    return { isValid: false, error: 'Email is required' };
  }
  
  if (email.length > authValidationRules.email.maxLength) {
    return { isValid: false, error: `Email must be no more than ${authValidationRules.email.maxLength} characters` };
  }
  
  if (!validator.isEmail(email)) {
    return { isValid: false, error: 'Invalid email format' };
  }
  
  return { isValid: true };
};

/**
 * Validates password strength
 */
export const validatePassword = (password: string): { isValid: boolean; error?: string } => {
  if (!password || typeof password !== 'string') {
    return { isValid: false, error: 'Password is required' };
  }
  
  if (password.length < authValidationRules.password.minLength) {
    return { isValid: false, error: `Password must be at least ${authValidationRules.password.minLength} characters` };
  }
  
  if (password.length > authValidationRules.password.maxLength) {
    return { isValid: false, error: `Password must be no more than ${authValidationRules.password.maxLength} characters` };
  }
  
  return { isValid: true };
};
