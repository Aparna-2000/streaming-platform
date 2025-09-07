import crypto from 'crypto';
import { Request } from 'express';

export interface DeviceFingerprint {
  userAgent: string;
  acceptLanguage: string;
  acceptEncoding: string;
  ipAddress: string;
  fingerprint: string;
}

export function generateDeviceFingerprint(req: Request): DeviceFingerprint {
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const acceptLanguage = req.headers['accept-language'] || 'Unknown';
  const acceptEncoding = req.headers['accept-encoding'] || 'Unknown';
  const ipAddress = req.ip || req.connection.remoteAddress || 'Unknown';

  // Create a hash of device characteristics
  const fingerprintData = `${userAgent}|${acceptLanguage}|${acceptEncoding}|${ipAddress}`;
  const fingerprint = crypto.createHash('sha256').update(fingerprintData).digest('hex');

  return {
    userAgent,
    acceptLanguage,
    acceptEncoding,
    ipAddress,
    fingerprint
  };
}

export function validateDeviceFingerprint(stored: DeviceFingerprint, current: DeviceFingerprint): {
  isValid: boolean;
  riskScore: number;
  reasons: string[];
} {
  const reasons: string[] = [];
  let riskScore = 0;

  // Exact fingerprint match
  if (stored.fingerprint === current.fingerprint) {
    return { isValid: true, riskScore: 0, reasons: [] };
  }

  // Check individual components
  if (stored.userAgent !== current.userAgent) {
    reasons.push('User-Agent mismatch');
    riskScore += 30;
  }

  if (stored.ipAddress !== current.ipAddress) {
    reasons.push('IP address change');
    riskScore += 40;
  }

  if (stored.acceptLanguage !== current.acceptLanguage) {
    reasons.push('Accept-Language change');
    riskScore += 10;
  }

  if (stored.acceptEncoding !== current.acceptEncoding) {
    reasons.push('Accept-Encoding change');
    riskScore += 5;
  }

  // Risk assessment
  const isValid = riskScore < 50; // Threshold for blocking

  return { isValid, riskScore, reasons };
}
