import axios, { AxiosError, InternalAxiosRequestConfig, AxiosResponse } from 'axios';
import { User, LoginFormData, ApiResponse, WeatherData } from '../types';
import { tabSync } from '../utils/tabSync';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  withCredentials: true,
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem('accessToken');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Global error tracking for Brave browser debugging
(window as any).braveDebugLog = [];

// Track all network errors globally
window.addEventListener('error', (event) => {
  console.log('🌐 GLOBAL ERROR EVENT:', event);
  (window as any).braveDebugLog.push({
    type: 'global_error',
    message: event.message,
    filename: event.filename,
    timestamp: new Date().toISOString()
  });
});

window.addEventListener('unhandledrejection', (event) => {
  console.log('🌐 UNHANDLED PROMISE REJECTION:', event.reason);
  (window as any).braveDebugLog.push({
    type: 'unhandled_rejection',
    reason: event.reason,
    timestamp: new Date().toISOString()
  });
});

// Request interceptor to log all outgoing requests
api.interceptors.request.use(
  (config) => {
    console.log('🚀 AXIOS REQUEST INTERCEPTOR:', {
      method: config.method?.toUpperCase(),
      url: config.url,
      baseURL: config.baseURL,
      fullURL: `${config.baseURL || ''}${config.url || ''}`,
      headers: config.headers,
      timestamp: new Date().toISOString(),
      browser: navigator.userAgent.includes('Brave') ? 'Brave' : (navigator.userAgent.includes('Chrome') ? 'Chrome-based' : 'Other')
    });
    return config;
  },
  (error) => {
    console.error('🚀 REQUEST INTERCEPTOR ERROR:', error);
    return Promise.reject(error);
  }
);

// Track refresh state to prevent multiple simultaneous refresh attempts
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value: any) => void;
  reject: (reason?: any) => void;
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

// Global flag to prevent security interference during logout
let isLoggingOut = false;

export const setLoggingOut = (value: boolean) => {
  isLoggingOut = value;
  localStorage.setItem('isLoggingOut', value.toString());
};

// Response interceptor for token refresh and security breach detection
api.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error) => {
    console.log('🔍 AXIOS INTERCEPTOR TRIGGERED:', {
      status: error.response?.status,
      url: error.config?.url,
      method: error.config?.method,
      hasSecurityAlert: !!error.response?.data?.securityAlert,
      responseData: error.response?.data,
      timestamp: new Date().toISOString()
    });

    // FORCE IMMEDIATE ALERT FOR ANY 403 - DEBUG ONLY
    if (error.response?.status === 403) {
      console.log('🚨 403 DETECTED - FORCING IMMEDIATE ALERT');
      
      // Create overlay immediately for any 403
      const overlay = document.createElement('div');
      overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(255,0,0,0.9);
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: Arial, sans-serif;
      `;
      
      const modal = document.createElement('div');
      modal.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 8px;
        max-width: 600px;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        border: 3px solid red;
      `;
      
      modal.innerHTML = `
        <h1 style="color: red; margin-top: 0;">🚨 403 DETECTED</h1>
        <p style="margin: 15px 0; font-size: 18px;">Status: ${error.response?.status}</p>
        <p style="margin: 15px 0; font-size: 16px;">URL: ${error.config?.url}</p>
        <p style="margin: 15px 0; font-size: 16px;">Data: ${JSON.stringify(error.response?.data)}</p>
        <button onclick="this.parentElement.parentElement.remove()" 
                style="background: red; color: white; border: none; padding: 15px 30px; border-radius: 4px; cursor: pointer; font-size: 18px;">
          CLOSE DEBUG
        </button>
      `;
      
      overlay.appendChild(modal);
      document.body.appendChild(overlay);
      
      console.log('🚨 DEBUG OVERLAY CREATED FOR 403');
    }

    const originalRequest = error.config;
    
    // Skip processing for logout requests initiated by user
    const isLogoutRequest = originalRequest?.url?.includes('/auth/logout');
    const userInitiatedLogout = localStorage.getItem('isLoggingOut') === 'true';
    
    if (isLogoutRequest && userInitiatedLogout) {
      console.log('🚪 Skipping security checks - user initiated logout request');
      return Promise.reject(error);
    }

    // SECURITY ALERT DETECTION - Handle all token theft scenarios
    if (error.response?.status === 403 && 
        (error.response?.data as any)?.securityAlert && 
        (error.response?.data as any)?.action === 'FORCE_LOGOUT') {
      
      const securityData = error.response.data as any;
      const reason = securityData.details?.reason || 'UNKNOWN';
      
      console.log('🚨 SECURITY ALERT TRIGGERED:', {
        reason,
        details: securityData.details,
        message: securityData.message,
        browser: navigator.userAgent,
        timestamp: new Date().toISOString()
      });
      
      // Different alert messages based on security breach type
      let alertMessage = '🚨 SECURITY ALERT: ';
      
      switch (reason) {
        case 'CROSS_BROWSER_IP_VIOLATION':
          alertMessage += 'This token is being used from a different browser or IP address! All sessions terminated for security.';
          break;
        case 'CROSS_BROWSER_LOGIN_ATTEMPT':
          alertMessage += 'New login detected from a different browser or IP address! All your sessions are being terminated for security.';
          break;
        case 'DUPLICATE_TOKEN_USAGE':
          alertMessage += 'This token is being used simultaneously from multiple locations! Token theft detected - all sessions terminated.';
          break;
        case 'INVALID_TOKEN_USAGE':
          alertMessage += 'Invalid or tampered token detected! This may indicate a security breach - all sessions terminated.';
          break;
        case 'NO_ACTIVE_SESSION':
          alertMessage += 'No active session found for this token! Your session may have been compromised - please login again.';
          break;
        default:
          alertMessage += 'Suspicious activity detected on your account! All sessions terminated for security.';
      }
      
      // Brave-specific workaround: Create a visible overlay instead of relying on alert()
      const showSecurityAlert = (message: string) => {
        // Try alert first
        try {
          alert(message);
          console.log('🚨 Alert successful');
          return;
        } catch (e) {
          console.error('🚨 Alert blocked, using fallback:', e);
        }
        
        // Fallback: Create a modal-like overlay
        const overlay = document.createElement('div');
        overlay.style.cssText = `
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: rgba(0,0,0,0.8);
          z-index: 999999;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: Arial, sans-serif;
        `;
        
        const modal = document.createElement('div');
        modal.style.cssText = `
          background: white;
          padding: 20px;
          border-radius: 8px;
          max-width: 500px;
          text-align: center;
          box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        `;
        
        modal.innerHTML = `
          <h2 style="color: #d32f2f; margin-top: 0;">🚨 SECURITY ALERT</h2>
          <p style="margin: 15px 0; font-size: 16px;">${message}</p>
          <button onclick="this.parentElement.parentElement.remove()" 
                  style="background: #d32f2f; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 16px;">
            OK
          </button>
        `;
        
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
        
        // Auto-remove after 10 seconds
        setTimeout(() => {
          if (overlay.parentNode) {
            overlay.remove();
          }
        }, 10000);
        
        console.log('🚨 Security alert overlay created');
      };
      
      // Show the security alert
      showSecurityAlert(alertMessage);
      
      // Additional debugging - test if alert works at all
      try {
        console.log('🚨 Testing basic alert functionality...');
        alert('🧪 ALERT TEST: If you see this, alerts are working');
        console.log('🚨 Basic alert test successful');
      } catch (e) {
        console.error('🚨 Basic alert test failed:', e);
      }
      
      // Immediate security cleanup
      console.log('🚨 Performing security cleanup...');
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      
      // Broadcast security logout to all tabs
      try {
        const broadcastChannel = new BroadcastChannel('auth-sync');
        broadcastChannel.postMessage({
          type: 'SECURITY_LOGOUT',
          message: alertMessage,
          reason: reason,
          timestamp: new Date().toISOString()
        });
        console.log('📡 Security logout broadcasted to all tabs');
        broadcastChannel.close();
      } catch (e) {
        console.error('📡 BroadcastChannel failed, using localStorage fallback:', e);
      }
      
      // Fallback: localStorage event for cross-tab sync
      localStorage.setItem('auth-logout-sync', JSON.stringify({
        type: 'SECURITY_LOGOUT',
        message: alertMessage,
        reason: reason,
        timestamp: new Date().toISOString()
      }));
      
      console.log('💾 Security logout stored for cross-tab sync');
      
      // Immediate security cleanup
      localStorage.removeItem('currentUser');
      localStorage.removeItem('lastTokenValidation');
      localStorage.setItem('securityBreach', 'true');
      localStorage.setItem('securityReason', reason);
      
      // Broadcast security breach to all tabs
      tabSync.broadcastLogout(true);
      const channel = new BroadcastChannel('security-channel');
      channel.postMessage({ 
        type: 'SECURITY_BREACH', 
        reason,
        timestamp: new Date().toISOString()
      });
      
      // Force redirect to login with security notice
      window.location.href = '/login?security=breach&reason=' + encodeURIComponent(reason);
      
      return Promise.reject(error);
    }
    

    // Handle 401 errors for token refresh
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
        console.log('🔄 Attempting token refresh...');
        const response = await authService.refreshToken();
        
        if (response && response.accessToken) {
          console.log('✅ Token refresh successful');
          localStorage.setItem('accessToken', response.accessToken);
          
          // Update the authorization header for the original request
          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${response.accessToken}`;
          }
          
          processQueue(null, response.accessToken);
          
          // Retry the original request
          return api(originalRequest);
        } else {
          throw new Error('No access token in refresh response');
        }
      } catch (refreshError) {
        console.error('❌ Token refresh failed:', refreshError);
        processQueue(refreshError, null);
        
        // Clear tokens and redirect to login
        localStorage.removeItem('accessToken');
        tabSync.broadcastLogout(false);
        
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

// Auth Service
export const authService = {
  async login(credentials: LoginFormData): Promise<{ user: User; accessToken: string } | null> {
    try {
      console.log('🔑 AuthService: Attempting login with:', { username: credentials.username, password: '[HIDDEN]' });
      console.log('🔑 AuthService: API URL:', `${API_BASE_URL}/auth/login`);
      
      const response = await api.post('/auth/login', credentials);
      
      console.log('🔑 AuthService: Login response received:', {
        status: response.status,
        success: response.data.success,
        hasUser: !!response.data.user,
        hasAccessToken: !!response.data.accessToken,
        message: response.data.message
      });
      
      if (response.data.success && response.data.user && response.data.accessToken) {
        const { user, accessToken } = response.data;
        localStorage.setItem('accessToken', accessToken);
        
        // Broadcast login to all tabs
        try {
          const broadcastChannel = new BroadcastChannel('auth-sync');
          broadcastChannel.postMessage({
            type: 'LOGIN',
            accessToken: accessToken,
            user: user,
            timestamp: new Date().toISOString()
          });
          console.log('📡 Login broadcasted to all tabs');
          broadcastChannel.close();
        } catch (e) {
          console.error('📡 BroadcastChannel failed for login:', e);
        }
        
        // Fallback: localStorage event for cross-tab sync
        localStorage.setItem('auth-login-sync', JSON.stringify({
          type: 'LOGIN',
          accessToken: accessToken,
          user: user,
          timestamp: new Date().toISOString()
        }));
        
        console.log('💾 Login stored for cross-tab sync');
        
        console.log('✅ AuthService: Login successful for user:', user.username);
        return { user, accessToken };
      }
      
      console.log('❌ AuthService: Login failed - missing user or accessToken in response');
      return null;
    } catch (error: any) {
      console.error('❌ AuthService: Login error details:', {
        message: error.message,
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
        url: error.config?.url,
        baseURL: error.config?.baseURL
      });
      
      // Check if backend is unreachable
      if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
        console.error('🚨 Backend server appears to be down or unreachable');
        console.error('🚨 Make sure backend is running on:', API_BASE_URL);
      }
      
      throw error;
    }
  },

  async register(userData: LoginFormData): Promise<{ user: User; accessToken: string } | null> {
    try {
      const response = await api.post<ApiResponse<{ user: User; accessToken: string }>>('/auth/register', userData);
      
      if (response.data.success && response.data.data) {
        const { user, accessToken } = response.data.data;
        localStorage.setItem('accessToken', accessToken);
        return { user, accessToken };
      }
      return null;
    } catch (error) {
      console.error('Registration error:', error);
      throw error;
    }
  },

  async logout(): Promise<void> {
    try {
      // Set flag to indicate user-initiated logout
      localStorage.setItem('isLoggingOut', 'true');
      
      await api.post('/auth/logout');
      
      // Clean up
      localStorage.removeItem('isLoggingOut');
    } catch (error) {
      console.error('Logout error:', error);
      // Clean up even if logout request fails
      localStorage.removeItem('isLoggingOut');
    }
  },

  async refreshToken(): Promise<{ accessToken: string } | null> {
    try {
      const response = await api.post<ApiResponse<{ accessToken: string }>>('/auth/refresh-token');
      
      if (response.data.success && response.data.data) {
        return response.data.data;
      }
      return null;
    } catch (error) {
      console.error('Token refresh error:', error);
      throw error;
    }
  },

  async getCurrentUser(): Promise<User | null> {
    try {
      const response = await api.get<ApiResponse<User>>('/auth/me');
      
      if (response.data.success && response.data.data) {
        return response.data.data;
      }
      return null;
    } catch (error) {
      console.error('Get current user error:', error);
      throw error;
    }
  },
};

// Test function to simulate cross-browser access detection
export const testCrossBrowserDetection = async () => {
  try {
    console.log('🧪 Testing cross-browser detection...');
    console.log('🧪 Browser:', navigator.userAgent);
    console.log('🧪 Current timestamp:', new Date().toISOString());
    
    // Make a request that should trigger device/IP validation
    const response = await api.get('/auth/me');
    console.log('✅ Request successful - no security breach detected');
    return response.data;
  } catch (error: any) {
    console.log('🔍 Test error response:', error.response?.status, error.response?.data);
    console.log('🔍 Full error object:', error);
    
    if (error.response?.status === 403 && error.response?.data?.securityAlert) {
      console.log('✅ Security breach detected successfully!');
      console.log('🚨 Security alert data:', error.response.data);
      
      // Force popup to show in test scenario
      const testMessage = '🧪 TEST ALERT: Security breach detected! This token is being used from a different browser. All sessions will be terminated.';
      console.log('🧪 Forcing test popup:', testMessage);
      
      // Multiple attempts to show popup
      setTimeout(() => {
        alert(testMessage);
        console.log('🧪 Test popup displayed via setTimeout');
      }, 50);
      
      try {
        alert(testMessage);
        console.log('🧪 Test popup displayed immediately');
      } catch (e) {
        console.error('🧪 Failed to show test popup:', e);
      }
      
      return { securityBreachDetected: true, data: error.response.data };
    }
    
    console.log('❌ No security breach detected');
    throw error;
  }
};

// Debug function to test popup functionality
export const testPopupFunctionality = () => {
  console.log('🧪 Testing popup functionality...');
  
  // Test 1: Basic alert
  try {
    alert('🧪 TEST 1: Basic alert test');
    console.log('✅ Basic alert works');
  } catch (e) {
    console.error('❌ Basic alert failed:', e);
  }
  
  // Test 2: setTimeout alert
  setTimeout(() => {
    try {
      alert('🧪 TEST 2: setTimeout alert test');
      console.log('✅ setTimeout alert works');
    } catch (e) {
      console.error('❌ setTimeout alert failed:', e);
    }
  }, 100);
  
  // Test 3: Confirm dialog
  try {
    console.log('🧪 TEST 3: Would show confirm dialog (skipped due to ESLint restrictions)');
    console.log('✅ Confirm dialog test skipped');
  } catch (e) {
    console.error('❌ Confirm dialog failed:', e);
  }
  
  // Test 4: Check if popups are blocked
  console.log('🧪 Popup blocker status:', {
    userAgent: navigator.userAgent,
    cookieEnabled: navigator.cookieEnabled,
    onLine: navigator.onLine
  });
};

// Make functions available globally for console testing
(window as any).testCrossBrowserDetection = testCrossBrowserDetection;
(window as any).testPopupFunctionality = testPopupFunctionality;
(window as any).debugSecurityAlert = () => {
  console.log('🧪 Manual security alert test...');
  const alertMessage = '🚨 MANUAL TEST: Security breach detected!';
  
  console.log('🧪 Attempting alert...');
  try {
    alert(alertMessage);
    console.log('✅ Manual alert successful');
  } catch (e) {
    console.error('❌ Manual alert failed:', e);
  }
  
  setTimeout(() => {
    try {
      alert(alertMessage + ' (Delayed)');
      console.log('✅ Manual delayed alert successful');
    } catch (e) {
      console.error('❌ Manual delayed alert failed:', e);
    }
  }, 200);
};

console.log('🧪 Debug functions loaded. Available in console:');
console.log('- testCrossBrowserDetection()');
console.log('- testPopupFunctionality()');
console.log('- debugSecurityAlert()');

// Weather Service
export const weatherService = {
  async getWeather(city: string): Promise<WeatherData | null> {
    try {
      const response = await api.get<ApiResponse<WeatherData>>(`/weather?city=${encodeURIComponent(city)}`);
      
      if (response.data.success && response.data.data) {
        return response.data.data;
      }
      return null;
    } catch (error) {
      console.error('Weather error:', error);
      throw error;
    }
  },
};

export default api;