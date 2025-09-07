-- Migration: Add token usage log table for duplicate token detection
-- This table tracks token usage to detect simultaneous usage from multiple locations

CREATE TABLE IF NOT EXISTS token_usage_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  token_hash VARCHAR(64) NOT NULL,
  user_id INT NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  device_info TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  INDEX idx_token_hash (token_hash),
  INDEX idx_user_id (user_id),
  INDEX idx_created_at (created_at),
  
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add unique constraint to prevent duplicate entries for same token/ip/device combination
ALTER TABLE token_usage_log 
ADD UNIQUE KEY unique_token_usage (token_hash, ip_address, device_info(255));
