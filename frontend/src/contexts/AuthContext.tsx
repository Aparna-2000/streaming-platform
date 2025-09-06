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

    const handleCrossTabLogout = () => {
      setUser(null);
      setLoading(false);
    };

    const handleCrossTabTokenRefresh = (event: CustomEvent) => {
      // Token updated, user state remains the same
      console.log('Token refreshed in another tab');
    };

    window.addEventListener('auth:login', handleCrossTabLogin as EventListener);
    window.addEventListener('auth:logout', handleCrossTabLogout);
    window.addEventListener('auth:token-refresh', handleCrossTabTokenRefresh as EventListener);

    return () => {
      window.removeEventListener('auth:login', handleCrossTabLogin as EventListener);
      window.removeEventListener('auth:logout', handleCrossTabLogout);
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
      const token = localStorage.getItem('accessToken');
      if (!token) {
        setLoading(false);
        return;
      }

      try {
        // Try to get current user info from the backend
        const response = await authService.getCurrentUser();
        if (response) {
          setUser(response);
        }
      } catch (error) {
        console.error('Failed to validate existing token:', error);
        // Clear invalid token
        localStorage.removeItem('accessToken');
      } finally {
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