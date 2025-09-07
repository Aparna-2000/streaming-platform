import express, { Express, Request, Response, NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { login, register, refreshToken, logout, getCurrentUser } from "./controllers/authController";
import { authenticateToken } from './middleware/auth';
import { verifyPasswordForSensitiveOp, changeEmail, changePassword } from './controllers/sessionController';
import { loginRateLimit, registerRateLimit, refreshRateLimit, passwordRateLimit } from './middleware/authRateLimit';
import securityRoutes from './routes/security';
import validator from 'validator';
import xss from 'xss';

// Load environment variables early
dotenv.config();

const app: Express = express();

const PORT = process.env.PORT || 5000;
const isProduction = process.env.NODE_ENV === "production";

// Trust first proxy (important if behind a proxy like nginx, Heroku, etc.)
app.set('trust proxy', 1);

/**
 * Security middleware
 * - helmet: sensible security headers
 * - CORS: allow local dev + configured frontend
 */
app.disable("x-powered-by");
app.use(
  helmet({
    // If you serve images or other cross-origin assets, you may need this:
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

const allowedOrigins = new Set<string>([
  "http://localhost:3000",
  "https://localhost:3000",
  ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : []),
]);

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no Origin (e.g., curl, mobile apps, Postman)
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token", "X-Requested-With"],
  exposedHeaders: ["set-cookie"],
};
app.use(cors(corsOptions));
// Explicit preflight for edge cases
app.options("*", cors(corsOptions));

/**
 * Rate limiting
 * - Keep generous limits in dev, tighter in prod
 */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { success: false, message: 'Too many requests, please try again later.' }
});

// Apply rate limiting to all requests
app.use(limiter);

/**
 * Request logging (minimal, targeted)
 */
app.use((req, _res, next) => {
  if (req.url.includes("/auth/me") && req.method === "GET") {
    console.log(`🔍 GET /auth/me @ ${new Date().toISOString()}`);
  }
  if (req.url.includes("/auth/login") && req.method === "POST") {
    console.log(`🔐 POST /auth/login @ ${new Date().toISOString()}`);
  }
  next();
});

/**
 * Parsers
 */
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/**
 * IMPORTANT:
 * - No server-side session storage. We rely on **JWT access tokens (~15 min)**.
 * - `authenticateToken` must verify/attach decoded claims to `req.user`.
 * - Protected routes should use `authenticateToken` middleware.
 * - Sensitive operations (e.g., password changes) should use `verifyPasswordForSensitiveOp` middleware.
 

/**
 * Health check
 */
app.get("/health", (_req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

/**
 * Input sanitization middleware
 */
function sanitizeInputs(allowedInputs: string[]) {
  return (req: Request, _res: Response, next: NextFunction) => {
    console.log('🧹 Sanitization middleware called for:', allowedInputs);
    console.log('📤 Original body:', req.body);
    
    if (req.body && typeof req.body === 'object') {
      for (const input of allowedInputs) {
        if (req.body[input] && typeof req.body[input] === 'string') {
          const original = req.body[input];
          
          // Trim whitespace
          let sanitized = validator.trim(req.body[input]);
          
          // Escape HTML entities to prevent XSS
          sanitized = validator.escape(sanitized);
          
          // Filter XSS attempts
          sanitized = xss(sanitized, {
            whiteList: {}, // No HTML tags allowed
            stripIgnoreTag: true,
            stripIgnoreTagBody: ['script']
          });
          
          req.body[input] = sanitized;
          console.log(`🔄 ${input}: "${original}" → "${sanitized}"`);
        }
      }
    }
    
    console.log('📥 Sanitized body:', req.body);
    next();
  };
}

app.use('/security', securityRoutes);

/**
 * Auth routes (JWT-based)
 * - /auth/login issues short-lived access tokens (~15m)
 * - /auth/refresh-token issues a new access token using a valid refresh token
 * - /auth/logout can revoke refresh tokens server-side
 * - /auth/me returns current user from verified JWT
 */
app.post("/auth/register", registerRateLimit, sanitizeInputs(['username', 'email', 'password']), register);
app.post("/auth/login", loginRateLimit, sanitizeInputs(['username', 'password']), login);
app.post("/auth/refresh-token", refreshRateLimit, refreshToken);
app.post("/auth/logout", authenticateToken, logout);
app.get("/auth/me", authenticateToken, getCurrentUser);

/**
 * Session routes (sensitive operations)
 */
app.post("/auth/session/verify-password", authenticateToken, passwordRateLimit, verifyPasswordForSensitiveOp);
app.post("/auth/session/change-email", authenticateToken, changeEmail);
app.post("/auth/session/change-password", authenticateToken, changePassword);

/**
 * Example protected route
 */
app.get("/protected", authenticateToken, (req: any, res: Response) => {
  res.json({
    message: "This is a protected route",
    user: req.user,
  });
});

/**
 * Error handling
 */
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err?.stack || err);
  // If CORS rejected the origin, return a 403 for clarity
  if (err?.message === "Not allowed by CORS") {
    return res.status(403).json({ success: false, message: "CORS: Origin not allowed" });
  }
  res.status(500).json({ success: false, message: "Something went wrong!" });
});

/**
 * 404 handler
 */
app.use("*", (req, res) => {
  console.log(`❌ 404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ success: false, message: "Route not found" });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

export default app;
