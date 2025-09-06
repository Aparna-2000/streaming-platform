-- Migration: Add refresh_tokens table for better token revocation control
-- This allows tracking and revoking specific refresh tokens per user

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME NULL,
    device_info VARCHAR(255) NULL,
    ip_address VARCHAR(45) NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_token_hash (token_hash),
    INDEX idx_expires_at (expires_at)
);

-- Clean up expired tokens (optional cleanup job)
-- DELETE FROM refresh_tokens WHERE expires_at < NOW() AND revoked_at IS NULL;
