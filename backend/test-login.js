const axios = require('axios');
const bcrypt = require('bcrypt');

async function testLogin() {
  const baseUrl = 'http://localhost:5000';
  
  // Test user credentials from the database
  const testUsers = [
    { username: 'testuser', password: 'testpass' },
    { username: 'admin', password: 'admin123' },
    { username: 'demo', password: 'demo123' }
  ];

  for (const user of testUsers) {
    console.log(`\nTesting login for user: ${user.username}`);
    console.log('='.repeat(40));
    
    try {
      // 1. Attempt login
      console.log('1. Attempting login...');
      const loginResponse = await axios.post(`${baseUrl}/auth/login`, {
        username: user.username,
        password: user.password
      }, {
        headers: { 'Content-Type': 'application/json' },
        withCredentials: true
      });
      
      console.log('Login Response:', {
        status: loginResponse.status,
        data: loginResponse.data
      });
      
      if (loginResponse.data.success && loginResponse.data.data?.accessToken) {
        const token = loginResponse.data.data.accessToken;
        
        // 2. Test protected route
        console.log('\n2. Testing protected route...');
        try {
          const protectedResponse = await axios.get(`${baseUrl}/api/protected`, {
            headers: {
              'Authorization': `Bearer ${token}`
            },
            withCredentials: true
          });
          console.log('Protected Route Response:', {
            status: protectedResponse.status,
            data: protectedResponse.data
          });
        } catch (error) {
          console.error('Error accessing protected route:', error.response?.data || error.message);
        }
        
        // 3. Test refresh token
        console.log('\n3. Testing refresh token...');
        try {
          const refreshResponse = await axios.post(
            `${baseUrl}/auth/refresh-token`,
            {},
            {
              headers: { 'Content-Type': 'application/json' },
              withCredentials: true
            }
          );
          console.log('Refresh Token Response:', {
            status: refreshResponse.status,
            data: refreshResponse.data
          });
        } catch (error) {
          console.error('Error refreshing token:', error.response?.data || error.message);
        }
      }
      
    } catch (error) {
      console.error('Login Error:', error.response?.data || error.message);
      
      // If it's an invalid credentials error, try with a hashed password
      if (error.response?.data?.message === 'Invalid credentials') {
        console.log('\nTrying with hashed password...');
        try {
          // Get the user's hashed password from the database
          const mysql = require('mysql2/promise');
          const connection = await mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: '',
            database: 'streaming_platform'
          });
          
          const [rows] = await connection.execute(
            'SELECT password_hash FROM users WHERE username = ?',
            [user.username]
          );
          
          if (rows.length > 0) {
            const hashedPassword = rows[0].password_hash;
            console.log(`Hashed password for ${user.username}:`, hashedPassword);
            
            // Try to verify the password
            const isMatch = await bcrypt.compare(user.password, hashedPassword);
            console.log(`Password match for ${user.username}:`, isMatch);
            
            if (!isMatch) {
              console.log(`\nPossible issue: The password for ${user.username} doesn't match the hash in the database`);
              console.log('You might need to reset the password for this user.');
            }
          }
          
          await connection.end();
        } catch (dbError) {
          console.error('Database error:', dbError.message);
        }
      }
    }
  }
}

testLogin().catch(console.error);
