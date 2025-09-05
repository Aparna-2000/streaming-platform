const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

async function setupDatabase() {
  let connection;
  
  try {
    // Connect to MySQL (without specifying database initially)
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
    });

    console.log('Connected to MySQL server');

    // Create database
    await connection.execute(`CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME || 'streaming_platform'}`);
    console.log('Database created/verified');

    // Use the database
    await connection.query(`USE ${process.env.DB_NAME || 'streaming_platform'}`);

    // Create users table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    console.log('Users table created/verified');

    // Create sessions table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
        expires INT(11) UNSIGNED NOT NULL,
        data MEDIUMTEXT COLLATE utf8mb4_bin,
        PRIMARY KEY (session_id)
      )
    `);
    console.log('Sessions table created/verified');

    // Create test users
    const testUsers = [
      { username: 'testuser', email: 'test@example.com', password: 'password123' },
      { username: 'admin', email: 'admin@example.com', password: 'admin123' },
      { username: 'demo', email: 'demo@example.com', password: 'demo123' }
    ];

    for (const user of testUsers) {
      // Check if user already exists
      const [existing] = await connection.execute(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        [user.username, user.email]
      );

      if (existing.length === 0) {
        // Hash password
        const password_hash = await bcrypt.hash(user.password, 12);
        
        // Insert user
        await connection.execute(
          'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
          [user.username, user.email, password_hash]
        );
        console.log(`✅ Created test user: ${user.username} (password: ${user.password})`);
      } else {
        console.log(`⚠️  User ${user.username} already exists`);
      }
    }

    console.log('\n🎉 Database setup complete!');
    console.log('\n📝 Test Login Credentials:');
    console.log('Username: testuser | Password: password123');
    console.log('Username: admin    | Password: admin123');
    console.log('Username: demo     | Password: demo123');

  } catch (error) {
    console.error('❌ Database setup failed:', error.message);
    
    if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.log('\n💡 Try running: brew services start mysql');
      console.log('💡 Or set up MySQL root password in .env file');
    } else if (error.code === 'ECONNREFUSED') {
      console.log('\n💡 MySQL server is not running. Try: brew services start mysql');
    }
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

setupDatabase();
