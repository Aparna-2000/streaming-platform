import axios, { AxiosResponse } from 'axios';
import { tabSync } from '../utils/tabSync';
import { showSecurityAlert } from '../utils/securityAlert';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

// Create axios instance with interceptors
const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true, // Important for cookies
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for token refresh and security alerts
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Handle security breach alerts
    if (error.response?.data?.securityAlert && error.response?.data?.action === 'FORCE_LOGOUT') {
      console.log('AuthService: Security breach detected, showing alert');
      console.log('AuthService: Error response:', error.response.data);
      
      // Show custom security alert popup (without browser prefix)
      await showSecurityAlert('🚨 SECURITY ALERT: Suspicious activity detected on your account. All sessions have been terminated for your protection. Please log in again.');
      
      // Force logout immediately with tab sync (pass security flag)
      localStorage.removeItem('accessToken');
      console.log('AuthService: Broadcasting security logout to all tabs');
      tabSync.broadcastLogout(true); // Pass true for security alert
      
      // Clear any loading states and force immediate redirect
      setTimeout(() => {
        console.log('AuthService: Forcing redirect to login');
        // Force hard redirect to ensure clean state
        window.location.replace('/login');
      }, 100); // Shorter delay since custom modal is already dismissed
      
      return Promise.reject(error);
    }

    // Handle token refresh for 401 errors
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshResponse = await axios.post(`${API_BASE_URL}/auth/refresh-token`, {}, {
          withCredentials: true,
        });

        const { accessToken } = refreshResponse.data;
        localStorage.setItem('accessToken', accessToken);
        
        // Broadcast token refresh to other tabs
        tabSync.broadcastTokenRefresh(accessToken);

        // Retry original request with new token
        originalRequest.headers.Authorization = `Bearer ${accessToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh failed, redirect to login with tab sync
        localStorage.removeItem('accessToken');
        tabSync.broadcastLogout();
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export interface User {
  id: number;
  username: string;
  email: string;
  role?: string;
}

export interface LoginResponse {
  success: boolean;
  message: string;
  accessToken: string;
  user: {
    id: number;
    username: string;
    email: string;
    role: string;
  };
}

export interface RegisterResponse {
  success: boolean;
  message: string;
  user?: {
    id: number;
    username: string;
    email: string;
    role: string;
  };
}

class AuthService {
  async login(username: string, password: string): Promise<LoginResponse> {
    const response: AxiosResponse<LoginResponse> = await api.post('/auth/login', {
      username,
      password,
    });
    
    if (response.data.success && response.data.accessToken) {
      localStorage.setItem('accessToken', response.data.accessToken);
    }
    
    return response.data;
  }

  async register(username: string, email: string, password: string): Promise<RegisterResponse> {
    const response: AxiosResponse<RegisterResponse> = await api.post('/auth/register', {
      username,
      email,
      password,
    });
    
    // Registration doesn't return accessToken, user needs to login separately
    return response.data;
  }

  async getCurrentUser(): Promise<User> {
    const response: AxiosResponse<{ success: boolean; user: User }> = await api.get('/auth/me');
    return response.data.user;
  }

  async logout(): Promise<void> {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('accessToken');
    }
  }

  async refreshToken(): Promise<string> {
    const response: AxiosResponse<LoginResponse> = await api.post('/auth/refresh-token');
    const { accessToken } = response.data;
    localStorage.setItem('accessToken', accessToken);
    return accessToken;
  }
}

export default new AuthService();
