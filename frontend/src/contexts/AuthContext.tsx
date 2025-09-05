import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { User, AuthContextType, LoginResponse } from '../types';
import { authService } from '../services/api';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
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

  // No initial auth check - we'll rely on the login response
  useEffect(() => {
    // Check for existing token on mount
    const token = localStorage.getItem('accessToken');
    if (!token) {
      setLoading(false);
    }
  }, []);

  const login = async (username: string, password: string): Promise<LoginResponse> => {
    try {
      if (!username || !password) {
        return { success: false, message: 'Please enter both username and password' };
      }
      
      setLoading(true);
      console.log('AuthContext: Attempting login...');
      const response = await authService.login({ username, password });
      console.log('AuthContext: Login response received:', response);
      
      if (response.success) {
        // If we have user data in the response, use it
        if (response.data?.user) {
          setUser(response.data.user);
          console.log('AuthContext: User set from login response');
        } else {
          // If login was successful but no user data, create a minimal user object
          const minimalUser: User = { 
            id: 0, // Temporary ID, should be replaced by actual ID from backend
            username,
            email: `${username}@example.com` // Default email since it's required
          };
          setUser(minimalUser);
          console.log('AuthContext: Created minimal user from username');
        }
        return { success: true };
      }
      
      // If we get here, login was not successful
      const errorMessage = response.message || 'Invalid username or password';
      console.error('AuthContext: Login failed:', errorMessage);
      return { 
        success: false, 
        message: errorMessage
      };
      
    } catch (error: any) {
      console.error('AuthContext: Login error:', error);
      const errorMessage = error.response?.data?.message || 
                         error.message || 
                         'An unexpected error occurred during login';
      return { 
        success: false, 
        message: errorMessage
      };
    } finally {
      setLoading(false);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      setLoading(true);
      await authService.logout();
      setUser(null);
      // Clear any stored tokens
      localStorage.removeItem('accessToken');
    } catch (error) {
      console.error('Logout failed:', error);
      throw error; // Re-throw to allow error handling in components
    } finally {
      setLoading(false);
    }
  };

  const value: AuthContextType = {
    user,
    login,
    logout,
    loading,
    checkAuthStatus: async () => {
      // This is a no-op now since we're not using /auth/me
      // It's kept for backward compatibility
    },
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};