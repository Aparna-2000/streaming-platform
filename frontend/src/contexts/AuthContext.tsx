import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authService } from '../services/api';
import { tabSync } from '../utils/tabSync';
import { User } from '../types';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Listen for cross-tab auth events
  useEffect(() => {
    const handleCrossTabLogin = (event: CustomEvent) => {
      setUser(event.detail.user);
      setLoading(false);
    };

    const handleCrossTabLogout = async (event: CustomEvent) => {
      console.log('🚨 AuthContext: Cross-tab logout event received:', event);
      console.log('🚨 AuthContext: Event detail:', event.detail);
      console.log('🚨 AuthContext: Security alert flag:', event.detail?.securityAlert);
      
      // Immediately clear state to prevent race conditions
      setUser(null);
      setLoading(false);
      
      if (event.detail?.securityAlert) {
        console.log('🚨 AuthContext: Showing security alert popup...');
        alert('🚨 SECURITY ALERT: Suspicious activity detected. All sessions terminated.');
        console.log('🚨 AuthContext: Security alert popup shown');
      }
      
      console.log('🚨 AuthContext: Redirecting to login...');
      // Use setTimeout to ensure state updates are processed first
      setTimeout(() => {
        window.location.replace('/login');
      }, 0);
    };

    const handleCrossTabTokenRefresh = (event: CustomEvent) => {
      // Token updated, user state remains the same
      console.log('Token refreshed in another tab');
    };

    window.addEventListener('auth:login', handleCrossTabLogin as EventListener);
    window.addEventListener('auth:logout', handleCrossTabLogout as unknown as EventListener);
    window.addEventListener('auth:token-refresh', handleCrossTabTokenRefresh as EventListener);

    return () => {
      window.removeEventListener('auth:login', handleCrossTabLogin as EventListener);
      window.removeEventListener('auth:logout', handleCrossTabLogout as unknown as EventListener);
      window.removeEventListener('auth:token-refresh', handleCrossTabTokenRefresh as EventListener);
    };
  }, []);

  const checkAuth = async (): Promise<void> => {
    try {
      setLoading(true);
      const user = await authService.getCurrentUser();
      setUser(user);
    } catch (error) {
      console.error('Auth check failed:', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (username: string, password: string): Promise<void> => {
    try {
      setLoading(true);
      const response = await authService.login({ username, password });
      console.log('AuthContext: Login response:', response);
      if (response.success && response.data) {
        const userData = response.data;
        console.log('AuthContext: User data:', userData);
        
        // Store access token first
        localStorage.setItem('accessToken', userData.accessToken);
        
        // Update user state - check if user is nested
        const user = userData.user || userData;
        console.log('AuthContext: Setting user:', user);
        setUser(user);
        
        // Broadcast login to other tabs
        tabSync.broadcastLogin(user, userData.accessToken);
      } else {
        throw new Error(response.message || 'Login failed');
      }
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      setLoading(true);
      await authService.logout();
      setUser(null);
      
      // Broadcast logout to other tabs
      tabSync.broadcastLogout();
      
      // Clear stored tokens
      localStorage.removeItem('accessToken');
    } catch (error) {
      console.error('Logout failed:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  // Check authentication status on mount
  useEffect(() => {
    const initializeAuth = async () => {
      console.log('AuthContext: Initializing auth...');
      const token = localStorage.getItem('accessToken');
      
      if (!token) {
        console.log('AuthContext: No token found, setting loading to false');
        setLoading(false);
        return;
      }

      console.log('AuthContext: Token found, validating...');
      try {
        // Try to get current user info from the backend
        const response = await authService.getCurrentUser();
        if (response) {
          console.log('AuthContext: Token valid, setting user:', response);
          setUser(response);
        }
      } catch (error: any) {
        console.error('AuthContext: Token validation failed:', error);
        
        // Let the axios interceptor handle security breaches via TabSync
        // Regular token validation failure - just clear tokens
        localStorage.removeItem('accessToken');
        setUser(null);
      } finally {
        console.log('AuthContext: Setting loading to false');
        setLoading(false);
      }
    };

    initializeAuth();
  }, []);

  const value: AuthContextType = {
    user,
    loading,
    login,
    logout,
    checkAuth,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};