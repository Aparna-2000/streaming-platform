-- Add device fingerprint column for enhanced security
ALTER TABLE refresh_tokens 
ADD COLUMN device_fingerprint TEXT NULL AFTER ip_address;
