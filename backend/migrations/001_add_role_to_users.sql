-- Add role column to users table
ALTER TABLE users
ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user';

-- Update existing users to have the default role if the column was just added
-- This ensures any existing users get the default role
UPDATE users SET role = 'user' WHERE role IS NULL;

-- Add an index on the role column if you plan to query by role frequently
CREATE INDEX idx_users_role ON users(role);
