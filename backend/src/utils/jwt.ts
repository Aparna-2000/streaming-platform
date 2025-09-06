import jwt, { SignOptions, VerifyOptions, JwtPayload, Secret, Algorithm } from "jsonwebtoken";
import { env } from "../config/env";

export type AccessTokenClaims = {
  sub: string;            // user id
  role?: string | null;
};

const ALGO: Algorithm = "HS256";
const SECRET: Secret = env.JWT_ACCESS_SECRET as Secret;

// Audience helpers
function buildSignAudience(aud?: string): SignOptions["audience"] {
  if (!aud) return undefined;
  const parts = aud.split(",").map(s => s.trim()).filter(Boolean);
  return parts.length <= 1 ? parts[0] : parts; // string | string[]
}

function buildVerifyAudience(aud?: string): VerifyOptions["audience"] {
  if (!aud) return undefined;
  const parts = aud.split(",").map(s => s.trim()).filter(Boolean);
  if (parts.length <= 1) return parts[0]; // string
  // cast to the non-empty tuple type expected by VerifyOptions
  return parts as unknown as [string | RegExp, ...(string | RegExp)[]];
}

const signOptions: SignOptions = {
  algorithm: ALGO,
  issuer: env.JWT_ISSUER,
  audience: buildSignAudience(env.JWT_AUDIENCE),
};

const verifyOptions: VerifyOptions = {
  algorithms: [ALGO],
  issuer: env.JWT_ISSUER,
  audience: buildVerifyAudience(env.JWT_AUDIENCE),
};

/** Signs a short-lived access token (default 15 minutes). */
export function signAccessToken(
  claims: AccessTokenClaims,
  expiresIn: string | number = env.JWT_ACCESS_EXPIRES || "15m"
): string {
  const options: SignOptions = { 
    ...signOptions, 
    expiresIn: expiresIn as SignOptions["expiresIn"]
  };
  return jwt.sign(claims, SECRET, options);
}

/** Verifies an access token and returns its claims. Throws on invalid/expired. */
export function verifyAccessToken(token: string): AccessTokenClaims & JwtPayload {
  return jwt.verify(token, SECRET, verifyOptions) as JwtPayload & AccessTokenClaims;
}
