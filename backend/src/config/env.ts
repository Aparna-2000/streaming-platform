import dotenv from "dotenv";

dotenv.config();

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

export const env = {
  JWT_ACCESS_SECRET: required("JWT_ACCESS_SECRET"),
  JWT_ISSUER: process.env.JWT_ISSUER ?? "streaming-platform-api",
  JWT_AUDIENCE: process.env.JWT_AUDIENCE ?? "streaming-platform-web",
  // We’ll still default to 15m in code, but keep this here for transparency.
  JWT_ACCESS_EXPIRES: process.env.JWT_ACCESS_EXPIRES ?? "15m",
};
