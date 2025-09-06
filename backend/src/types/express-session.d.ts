import { Session, SessionData } from 'express-session';
import { Request as ExpressRequest } from 'express';

declare global {
  namespace Express {
    interface Request {
      user?: {
        sub: string;
        role?: string | null;
      };
    }
  }
}

declare module 'express-session' {
  interface SessionData {
    user?: {
      id: number;
      username: string;
      email: string;
    };
  }
}
