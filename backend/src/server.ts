import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import dotenv from 'dotenv';
import { login, register, refreshToken, logout, getCurrentUser } from './controllers/authController';
import { authenticateToken, AuthRequest } from './middleware/auth';

// Load environment variables
dotenv.config();

const app: Express = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
// CORS configuration
const corsOptions = {
  origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://localhost:3000',
      ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : [])
    ];
    
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
  exposedHeaders: ['set-cookie']
};

app.use(cors(corsOptions));

// Rate limiting (temporarily disabled for debugging)
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: process.env.NODE_ENV === 'production' ? 100 : 1000 // Higher limit for development
// });
// app.use(limiter);

// Request logging for debugging
app.use((req, res, next) => {
  if (req.url.includes('/auth/me')) {
    console.log(`🔍 GET /auth/me request at ${new Date().toISOString()}`);
  }
  if (req.url.includes('/auth/login') && req.method === 'POST') {
    console.log(`🔐 POST /auth/login request at ${new Date().toISOString()}`);
  }
  next();
});

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration with 15-minute expiration
const SESSION_EXPIRATION_MS = 15 * 60 * 1000; // 15 minutes
const isProduction = process.env.NODE_ENV === 'production';

app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'fallback-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProduction,
    httpOnly: true,
    maxAge: SESSION_EXPIRATION_MS,
    sameSite: isProduction ? 'none' : 'lax',
    path: '/',
    domain: isProduction ? '.yourdomain.com' : undefined // Set this to your domain in production
  },
  rolling: true, // Reset the expiration time on every request
  proxy: isProduction // Trust the reverse proxy for secure cookies in production
}));

// Trust first proxy in production
if (isProduction) {
  app.set('trust proxy', 1);
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Auth routes
app.post('/auth/register', register);
app.post('/auth/login', login);
app.post('/auth/refresh-token', refreshToken);
app.post('/auth/logout', authenticateToken, logout);
app.get('/auth/me', authenticateToken, getCurrentUser);

// Protected routes example
app.get('/protected', authenticateToken, (req: AuthRequest, res: Response) => {
  res.json({ 
    message: 'This is a protected route',
    user: req.user 
  });
});

// Error handling middleware
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Something went wrong!' 
  });
});

// 404 handler
app.use('*', (req, res) => {
  console.log(`❌ 404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ 
    success: false, 
    message: 'Route not found' 
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

export default app;
