// Augment Express's Request to include `user`
import "express";

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

export {};
