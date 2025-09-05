const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

async function updatePassword(username, newPassword) {
  const connection = await mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'streaming_platform'
  });

  try {
    // Hash the new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Update the password in the database
    const [result] = await connection.execute(
      'UPDATE users SET password_hash = ? WHERE username = ?',
      [hashedPassword, username]
    );
    
    console.log(`Password for ${username} has been updated successfully`);
    console.log('New hash:', hashedPassword);
    
    return hashedPassword;
  } catch (error) {
    console.error('Error updating password:', error);
    throw error;
  } finally {
    await connection.end();
  }
}

// Update admin password to 'admin123'
updatePassword('admin', 'admin123')
  .catch(console.error);
