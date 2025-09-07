const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

async function runMigration() {
  let connection;
  
  try {
    // Connect to database
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'streaming_platform'
    });

    console.log('Connected to database');

    // Read migration file
    const migrationPath = path.join(__dirname, 'migrations', '003_add_device_fingerprint_column.sql');
    const migrationSQL = fs.readFileSync(migrationPath, 'utf8');

    // Execute migration
    await connection.execute(migrationSQL);
    console.log('✅ Migration 003_add_device_fingerprint_column.sql executed successfully');

    // Verify the column was added
    const [columns] = await connection.execute(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'refresh_tokens' AND COLUMN_NAME = 'device_fingerprint'
    `, [process.env.DB_NAME || 'streaming_platform']);

    if (columns.length > 0) {
      console.log('✅ device_fingerprint column verified in refresh_tokens table');
    } else {
      console.log('❌ device_fingerprint column not found');
    }

  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    
    if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.log('\n💡 Try running: brew services start mysql');
      console.log('💡 Or check MySQL credentials in .env file');
    } else if (error.code === 'ECONNREFUSED') {
      console.log('\n💡 MySQL server is not running. Try: brew services start mysql');
    } else if (error.code === 'ER_DUP_FIELDNAME') {
      console.log('⚠️  Column already exists - migration already applied');
    }
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

runMigration();
