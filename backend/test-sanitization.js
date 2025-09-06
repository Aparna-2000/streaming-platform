const axios = require('axios');

const API_BASE = 'http://localhost:5000';

// Test cases for input sanitization
const testCases = [
  {
    name: 'XSS Script Tag Attack',
    data: {
      username: '<script>alert("XSS")</script>admin',
      password: 'password123'
    },
    expectedBehavior: 'Should sanitize script tags'
  },
  {
    name: 'HTML Injection',
    data: {
      username: '<img src=x onerror=alert(1)>admin',
      password: 'password123'
    },
    expectedBehavior: 'Should escape HTML entities'
  },
  {
    name: 'SQL Injection Attempt',
    data: {
      username: "admin'; DROP TABLE users; --",
      password: 'password123'
    },
    expectedBehavior: 'Should sanitize SQL injection attempts'
  },
  {
    name: 'Invalid Username Characters',
    data: {
      username: 'admin@#$%',
      password: 'password123'
    },
    expectedBehavior: 'Should reject invalid characters'
  },
  {
    name: 'Username Too Short',
    data: {
      username: 'ab',
      password: 'password123'
    },
    expectedBehavior: 'Should reject usernames < 3 characters'
  },
  {
    name: 'Username Too Long',
    data: {
      username: 'a'.repeat(31),
      password: 'password123'
    },
    expectedBehavior: 'Should reject usernames > 30 characters'
  },
  {
    name: 'Password Too Short',
    data: {
      username: 'admin',
      password: '12345'
    },
    expectedBehavior: 'Should reject passwords < 6 characters'
  },
  {
    name: 'Valid Input',
    data: {
      username: 'admin',
      password: 'password123'
    },
    expectedBehavior: 'Should accept valid input'
  }
];

// Registration test cases
const registerTestCases = [
  {
    name: 'XSS in Email',
    data: {
      username: 'testuser',
      email: '<script>alert("XSS")</script>@test.com',
      password: 'password123'
    },
    expectedBehavior: 'Should sanitize email XSS attempts'
  },
  {
    name: 'Invalid Email Format',
    data: {
      username: 'testuser',
      email: 'invalid-email',
      password: 'password123'
    },
    expectedBehavior: 'Should reject invalid email format'
  },
  {
    name: 'Valid Registration',
    data: {
      username: 'newuser123',
      email: 'newuser@test.com',
      password: 'password123'
    },
    expectedBehavior: 'Should accept valid registration'
  }
];

async function testEndpoint(endpoint, data, testName, expectedBehavior) {
  try {
    console.log(`\n🧪 Testing: ${testName}`);
    console.log(`📝 Expected: ${expectedBehavior}`);
    console.log(`📤 Sending:`, data);
    
    const response = await axios.post(`${API_BASE}${endpoint}`, data, {
      timeout: 5000,
      validateStatus: () => true // Don't throw on 4xx/5xx status codes
    });
    
    console.log(`📥 Status: ${response.status}`);
    console.log(`📥 Response:`, response.data);
    
    // Check if sanitization worked
    if (response.data.message) {
      console.log(`💬 Message: ${response.data.message}`);
    }
    
    return response;
  } catch (error) {
    console.error(`❌ Error testing ${testName}:`, error.message);
    return null;
  }
}

async function runTests() {
  console.log('🚀 Starting Input Sanitization Tests');
  console.log('=====================================');
  
  // Test login endpoint
  console.log('\n📋 TESTING LOGIN ENDPOINT');
  console.log('==========================');
  
  for (const testCase of testCases) {
    await testEndpoint('/auth/login', testCase.data, testCase.name, testCase.expectedBehavior);
    await new Promise(resolve => setTimeout(resolve, 500)); // Small delay between tests
  }
  
  // Test registration endpoint
  console.log('\n📋 TESTING REGISTRATION ENDPOINT');
  console.log('=================================');
  
  for (const testCase of registerTestCases) {
    await testEndpoint('/auth/register', testCase.data, testCase.name, testCase.expectedBehavior);
    await new Promise(resolve => setTimeout(resolve, 500)); // Small delay between tests
  }
  
  console.log('\n✅ All tests completed!');
  console.log('\n📊 SUMMARY:');
  console.log('- Check that XSS attempts return validation errors');
  console.log('- Verify invalid inputs are rejected with clear messages');
  console.log('- Confirm valid inputs are processed normally');
  console.log('- Look for sanitized data in server logs');
}

// Run tests if this file is executed directly
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { runTests, testEndpoint };
