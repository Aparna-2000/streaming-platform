import axios, { AxiosError, InternalAxiosRequestConfig, AxiosResponse } from 'axios';
import { User, LoginFormData, ApiResponse, WeatherData } from '../types';
import { tabSync } from '../utils/tabSync';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

// Helper function to handle API errors
const handleApiError = (error: any, defaultMessage: string) => {
  console.error('API Error:', error);
  return {
    success: false,
    message: error.response?.data?.message || error.message || defaultMessage,
  };
};

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  withCredentials: true, // Important for HttpOnly cookies
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests if it exists
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = localStorage.getItem('accessToken');
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 responses with automatic refresh and retry
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value?: any) => void;
  reject: (error?: any) => void;
}> = [];

const processQueue = (error: any, token: string | null = null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) {
      reject(error);
    } else {
      resolve(token);
    }
  });
  
  failedQueue = [];
};

api.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as any;

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // If already refreshing, queue this request
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(token => {
          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${token}`;
          }
          return api(originalRequest);
        }).catch(err => {
          return Promise.reject(err);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const refreshResponse = await authService.refreshToken();
        if (refreshResponse.success && refreshResponse.data?.accessToken) {
          const newToken = refreshResponse.data.accessToken;
          
          // Update localStorage
          localStorage.setItem('accessToken', newToken);
          
          // Broadcast token refresh to other tabs
          tabSync.broadcastTokenRefresh(newToken);
          
          processQueue(null, newToken);
          
          // Retry original request with new token
          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
          }
          return api(originalRequest);
        } else {
          throw new Error('Refresh failed');
        }
      } catch (refreshError) {
        processQueue(refreshError, null);
        localStorage.removeItem('accessToken');
        
        // Broadcast logout to other tabs
        tabSync.broadcastLogout();
        
        if (!window.location.pathname.includes('/login')) {
          window.location.href = '/login';
        }
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

const authService = {
  async login(credentials: LoginFormData): Promise<ApiResponse<{ user: User; accessToken: string }>> {
    try {
      console.log('🔑 Attempting login with credentials:', credentials);
      const response = await api.post('/auth/login', credentials);
      console.log('✅ Login response:', response.data);
      
      if (response.data.success && response.data.data?.accessToken) {
        localStorage.setItem('accessToken', response.data.data.accessToken);
      }
      return response.data;
    } catch (error: any) {
      return handleApiError(error, 'Login failed. Please check your credentials and try again.');
    }
  },

  async logout(): Promise<{ success: boolean; message?: string }> {
    try {
      await api.post('/auth/logout');
      localStorage.removeItem('accessToken');
      return { success: true };
    } catch (error: any) {
      return handleApiError(error, 'Logout failed');
    }
  },

  async refreshToken(): Promise<ApiResponse<{ accessToken: string }>> {
    try {
      const response = await api.post('/auth/refresh-token');
      if (response.data.success && response.data.data?.accessToken) {
        localStorage.setItem('accessToken', response.data.data.accessToken);
      }
      return response.data;
    } catch (error: any) {
      localStorage.removeItem('accessToken');
      throw error;
    }
  },

  async getCurrentUser(): Promise<User | null> {
    try {
      const token = localStorage.getItem('accessToken');
      if (!token) return null;
      
      const response = await api.get('/auth/me');
      if (response.data.success && response.data.user) {
        return response.data.user;
      }
      return null;
    } catch (error) {
      // Token is invalid, remove it
      localStorage.removeItem('accessToken');
      return null;
    }
  },

  isAuthenticated(): boolean {
    return !!localStorage.getItem('accessToken');
  }
};

const weatherService = {
  async getWeatherData(city: string = 'London'): Promise<ApiResponse<WeatherData>> {
    try {
      // Mock data for testing
      const mockWeatherData: WeatherData = {
        location: city,
        current: {
          temperature: Math.round(15 + Math.random() * 10),
          humidity: 60 + Math.round(Math.random() * 30),
          description: ['Sunny', 'Partly Cloudy', 'Cloudy', 'Rainy'][Math.floor(Math.random() * 4)],
          icon: ['01d', '02d', '03d', '09d', '10d', '11d', '13d', '50d'][Math.floor(Math.random() * 8)]
        },
        forecast: Array(5).fill(0).map((_, i) => {
          const date = new Date();
          date.setDate(date.getDate() + i + 1);
          return {
            date: date.toISOString(),
            temperature: {
              min: Math.round(10 + Math.random() * 10),
              max: Math.round(20 + Math.random() * 10)
            },
            description: ['Sunny', 'Partly Cloudy', 'Cloudy', 'Rainy', 'Thunderstorm'][Math.floor(Math.random() * 5)],
            icon: ['01d', '02d', '03d', '09d', '10d', '11d', '13d', '50d'][Math.floor(Math.random() * 8)]
          };
        })
      };
      
      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 500));
      
      return {
        success: true,
        data: mockWeatherData
      };
    } catch (error: any) {
      return handleApiError(error, 'Failed to fetch weather data');
    }
  },
};

// Test login function
const testLogin = async () => {
  console.log('🚀 Testing login functionality...');
  
  // Test 1: Try login with empty credentials
  console.log('\n🔍 Test 1: Empty credentials');
  const emptyCreds = await authService.login({ username: '', password: '' });
  console.log('Response:', emptyCreds.success ? '✅ Success' : '❌ Failed', emptyCreds);
  
  // Test 2: Try login with invalid credentials
  console.log('\n🔍 Test 2: Invalid credentials');
  const invalidCreds = await authService.login({ username: 'test', password: 'wrong' });
  console.log('Response:', invalidCreds.success ? '✅ Success' : '❌ Failed', invalidCreds);
  
  // Test 3: Try login with valid credentials (if available)
  console.log('\n🔍 Test 3: Valid credentials');
  const validCreds = await authService.login({ username: 'testuser', password: 'testpass' });
  console.log('Response:', validCreds.success ? '✅ Success' : '❌ Failed', validCreds);
  
  if (validCreds.success) {
    console.log('🔑 Access Token:', localStorage.getItem('accessToken'));
    console.log('👤 Current User:', await authService.getCurrentUser());
    console.log('🔒 Is Authenticated:', authService.isAuthenticated());
    
    // Test 4: Try accessing protected route
    console.log('\n🔍 Test 4: Access protected route');
    try {
      const response = await api.get('/protected-route');
      console.log('Protected route response:', response.data);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('Error accessing protected route:', errorMessage);
    }
    
    // Test 5: Logout
    console.log('\n🔍 Test 5: Logout');
    const logoutResult = await authService.logout();
    console.log('Logout result:', logoutResult);
    console.log('🔑 Access Token after logout:', localStorage.getItem('accessToken'));
    console.log('👤 Current User after logout:', await authService.getCurrentUser());
    console.log('🔒 Is Authenticated after logout:', authService.isAuthenticated());
  }
};

// Export services
export { authService, weatherService, testLogin };

// Export the api instance as default
export default api;