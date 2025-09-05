const axios = require('axios');

async function verifyLogin() {
  const baseUrl = 'http://localhost:5000';
  
  try {
    console.log('Testing admin login...');
    const response = await axios.post(
      `${baseUrl}/auth/login`,
      {
        username: 'admin',
        password: 'admin123'
      },
      {
        headers: { 'Content-Type': 'application/json' },
        withCredentials: true
      }
    );
    
    console.log('Login successful!');
    console.log('Response:', {
      status: response.status,
      data: response.data
    });
    
    if (response.data.success) {
      console.log('\nUser data:', response.data.data);
      console.log('Access token received:', !!response.data.data?.accessToken);
    }
    
  } catch (error) {
    console.error('Login failed:', error.response?.data || error.message);
  }
}

verifyLogin().catch(console.error);
