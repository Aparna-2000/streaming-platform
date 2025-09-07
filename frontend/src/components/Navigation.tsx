import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
} from '@mui/material';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const Navigation: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    console.log('Navigation: Logout button clicked');
    await logout();
  };

  const handleTestSecurity = async () => {
    console.log('Navigation: Testing cross-browser detection...');
    
    // Create a custom axios instance with different User-Agent header
    const testApi = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
      withCredentials: true,
      headers: {
        'User-Agent': 'TestBrowser/1.0 (Cross-Browser-Test)'
      }
    });
    
    // Add auth token
    const token = localStorage.getItem('accessToken');
    if (token) {
      testApi.defaults.headers.Authorization = `Bearer ${token}`;
    }
    
    try {
      console.log('Making test request with different User-Agent...');
      const result = await testApi.get('/auth/me');
      console.log('❌ Test failed - no security breach detected:', result.data);
      alert('❌ Test failed - security system did not detect cross-browser access');
    } catch (error: any) {
      console.log('🔍 Test error response:', error.response?.status, error.response?.data);
      
      if (error.response?.status === 403 && error.response?.data?.securityAlert) {
        console.log('✅ Security breach detected successfully!');
        alert('✅ SUCCESS: Security system detected cross-browser access!');
      } else {
        console.log('❌ Unexpected error:', error);
        alert('❌ Test failed with unexpected error');
      }
    }
  };

  const handleTestDuplicateToken = async () => {
    console.log('Navigation: Testing duplicate token usage...');
    
    const token = localStorage.getItem('accessToken');
    if (!token) {
      alert('❌ No token found - please login first');
      return;
    }
    
    // Simulate multiple simultaneous requests from different "locations"
    const testApi1 = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
      withCredentials: true,
      headers: {
        'User-Agent': 'Browser1/1.0 (Location-A)',
        'X-Forwarded-For': '192.168.1.100'
      }
    });
    
    const testApi2 = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
      withCredentials: true,
      headers: {
        'User-Agent': 'Browser2/1.0 (Location-B)',
        'X-Forwarded-For': '10.0.0.50'
      }
    });
    
    testApi1.defaults.headers.Authorization = `Bearer ${token}`;
    testApi2.defaults.headers.Authorization = `Bearer ${token}`;
    
    try {
      // Make simultaneous requests with same token from different "locations"
      console.log('Making simultaneous requests with same token...');
      const [result1, result2] = await Promise.all([
        testApi1.get('/auth/me'),
        testApi2.get('/auth/me')
      ]);
      
      console.log('❌ Test failed - duplicate token usage not detected');
      alert('❌ Test failed - system did not detect duplicate token usage');
    } catch (error: any) {
      console.log('🔍 Duplicate token test error:', error.response?.status, error.response?.data);
      
      if (error.response?.status === 403 && error.response?.data?.securityAlert) {
        console.log('✅ Duplicate token usage detected!');
        alert('✅ SUCCESS: System detected duplicate token usage!');
      } else {
        console.log('❌ Unexpected error:', error);
        alert('❌ Test failed with unexpected error');
      }
    }
  };

  const handleTestInvalidToken = async () => {
    console.log('Navigation: Testing invalid token detection...');
    
    // Create a fake/invalid token
    const fakeToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjoxNjAwMDA4NjQwfQ.FAKE_SIGNATURE_FOR_TESTING';
    
    const testApi = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
      withCredentials: true,
      headers: {
        'Authorization': `Bearer ${fakeToken}`
      }
    });
    
    try {
      console.log('Making request with invalid token...');
      const result = await testApi.get('/auth/me');
      console.log('❌ Test failed - invalid token not detected:', result.data);
      alert('❌ Test failed - system did not detect invalid token');
    } catch (error: any) {
      console.log('🔍 Invalid token test error:', error.response?.status, error.response?.data);
      
      if (error.response?.status === 403 && error.response?.data?.securityAlert) {
        console.log('✅ Invalid token detected!');
        alert('✅ SUCCESS: System detected invalid token!');
      } else {
        console.log('❌ Unexpected error:', error);
        alert('❌ Test failed with unexpected error');
      }
    }
  };

  const handleTestExpiredToken = async () => {
    console.log('Navigation: Testing expired token detection...');
    
    // Create a fake/expired token
    const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjoxNjAwMDAwMDAwfQ.SIGNATURE_FOR_TESTING';
    
    const testApi = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
      withCredentials: true,
      headers: {
        'Authorization': `Bearer ${expiredToken}`
      }
    });
    
    try {
      console.log('Making request with expired token...');
      const result = await testApi.get('/auth/me');
      console.log('❌ Test failed - expired token not detected:', result.data);
      alert('❌ Test failed - system did not detect expired token');
    } catch (error: any) {
      console.log('🔍 Expired token test error:', error.response?.status, error.response?.data);
      
      if (error.response?.status === 403 && error.response?.data?.securityAlert) {
        console.log('✅ Expired token detected!');
        alert('✅ SUCCESS: System detected expired token!');
      } else {
        console.log('❌ Unexpected error:', error);
        alert('❌ Test failed with unexpected error');
      }
    }
  };

  const handleTestPopup = () => {
    console.log('Navigation: Testing security popup manually...');
    // Manually trigger the security alert popup to test if it works
    alert('🚨 SECURITY ALERT: This token is being used from another browser/IP! All sessions terminated for security.');
    console.log('✅ Manual popup test completed');
  };

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
          Streaming Platform
        </Typography>
        {user && (
          <Box display="flex" alignItems="center" gap={2}>
            <Typography variant="body2">
              Welcome, {user.username}
            </Typography>
            <Button color="inherit" onClick={handleTestSecurity} size="small">
              Test Security
            </Button>
            <Button color="inherit" onClick={handleTestDuplicateToken} size="small">
              Test Duplicate Token
            </Button>
            <Button color="inherit" onClick={handleTestInvalidToken} size="small">
              Test Invalid Token
            </Button>
            <Button color="inherit" onClick={handleTestExpiredToken} size="small">
              Test Expired Token
            </Button>
            <Button color="inherit" onClick={handleTestPopup} size="small">
              Test Popup
            </Button>
            <Button color="inherit" onClick={handleLogout}>
              Logout
            </Button>
          </Box>
        )}
      </Toolbar>
    </AppBar>
  );
};

export default Navigation;
