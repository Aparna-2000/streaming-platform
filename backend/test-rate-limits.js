const axios = require('axios');

const BASE_URL = 'http://localhost:3001';

// Test configuration
const testConfig = {
  login: { endpoint: '/auth/login', limit: 5, window: '15 minutes' },
  register: { endpoint: '/auth/register', limit: 3, window: '1 hour' },
  refresh: { endpoint: '/auth/refresh-token', limit: 20, window: '15 minutes' }
};

async function testRateLimit(endpoint, maxAttempts, testData) {
  console.log(`\n🧪 Testing rate limit for ${endpoint}`);
  console.log(`Expected limit: ${maxAttempts} requests`);
  
  const results = [];
  
  for (let i = 1; i <= maxAttempts + 2; i++) {
    try {
      const response = await axios.post(`${BASE_URL}${endpoint}`, testData, {
        timeout: 5000,
        validateStatus: () => true // Don't throw on 4xx/5xx
      });
      
      results.push({
        attempt: i,
        status: response.status,
        rateLimited: response.status === 429,
        message: response.data?.message || 'No message'
      });
      
      console.log(`Attempt ${i}: ${response.status} - ${response.data?.message || 'Success'}`);
      
      // Small delay between requests
      await new Promise(resolve => setTimeout(resolve, 100));
      
    } catch (error) {
      results.push({
        attempt: i,
        status: 'ERROR',
        rateLimited: false,
        message: error.message
      });
      console.log(`Attempt ${i}: ERROR - ${error.message}`);
    }
  }
  
  return results;
}

async function runRateLimitTests() {
  console.log('🚀 Starting Auth Rate Limit Tests');
  console.log('=====================================');
  
  try {
    // Test 1: Login Rate Limiting
    const loginResults = await testRateLimit('/auth/login', 5, {
      username: 'nonexistent_user',
      password: 'wrong_password'
    });
    
    // Test 2: Registration Rate Limiting  
    const registerResults = await testRateLimit('/auth/register', 3, {
      username: 'testuser_' + Date.now(),
      email: 'test_' + Date.now() + '@example.com',
      password: 'testpassword123'
    });
    
    // Test 3: Token Refresh Rate Limiting (this will fail due to no token, but should still trigger rate limit)
    const refreshResults = await testRateLimit('/auth/refresh-token', 20, {});
    
    // Summary
    console.log('\n📊 Test Results Summary');
    console.log('========================');
    
    const analyzeResults = (results, testName, expectedLimit) => {
      const rateLimitedCount = results.filter(r => r.rateLimited).length;
      const successfulBeforeLimit = results.slice(0, expectedLimit).filter(r => !r.rateLimited).length;
      
      console.log(`\n${testName}:`);
      console.log(`  ✅ Successful requests before limit: ${successfulBeforeLimit}/${expectedLimit}`);
      console.log(`  🚫 Rate limited requests: ${rateLimitedCount}`);
      console.log(`  📈 Rate limiting working: ${rateLimitedCount > 0 ? 'YES' : 'NO'}`);
    };
    
    analyzeResults(loginResults, 'Login Rate Limit', 5);
    analyzeResults(registerResults, 'Register Rate Limit', 3);
    analyzeResults(refreshResults, 'Refresh Rate Limit', 20);
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

// Run the tests
runRateLimitTests().then(() => {
  console.log('\n✅ Rate limit testing completed');
  process.exit(0);
}).catch(error => {
  console.error('❌ Test suite failed:', error);
  process.exit(1);
});
