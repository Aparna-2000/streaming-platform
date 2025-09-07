import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User } from '../types';
import { authService } from '../services/api';
import { useNavigate } from 'react-router-dom';
import { browserSessionManager } from '../utils/browserSessionManager';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
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

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      console.log('AuthContext: Attempting login...');
      const result = await authService.login({ username, password });
      
      if (result) {
        console.log('AuthContext: Login successful, setting user:', result.user);
        setUser(result.user);
        
        // Store user data and validation timestamp immediately
        localStorage.setItem('currentUser', JSON.stringify(result.user));
        localStorage.setItem('lastTokenValidation', Date.now().toString());
        
        // Sync token across all tabs in same browser only
        browserSessionManager.syncTokenAcrossTabs(result.accessToken);
        
        return true;
      }
      
      console.log('AuthContext: Login failed');
      return false;
    } catch (error) {
      console.error('AuthContext: Login error:', error);
      return false;
    }
  };

  const logout = async (): Promise<void> => {
    try {
      console.log('AuthContext: Logging out...');
      // Set a flag to prevent any security interference during logout
      localStorage.setItem('isLoggingOut', 'true');
      await authService.logout();
    } catch (error) {
      console.error('AuthContext: Logout error:', error);
    } finally {
      // Clear all authentication data
      localStorage.removeItem('accessToken');
      localStorage.removeItem('currentUser');
      localStorage.removeItem('lastTokenValidation');
      localStorage.removeItem('isLoggingOut');
      
      // Clear user state
      setUser(null);
      
      // Logout all tabs in same browser
      browserSessionManager.logoutAllTabs('User initiated logout');
      
      // Use a timeout to ensure state is cleared before navigation
      setTimeout(() => {
        window.location.href = '/login';
      }, 100);
    }
  };

  // Check authentication status on mount and handle tab synchronization
  useEffect(() => {
    const initializeAuth = async () => {
      console.log('AuthContext: Initializing auth...');
      const token = localStorage.getItem('accessToken');
      
      if (!token) {
        console.log('AuthContext: No token found, setting loading to false');
        setLoading(false);
        return;
      }

      // ALWAYS try to use cached user data first for instant loading
      const currentUser = localStorage.getItem('currentUser');
      if (currentUser) {
        try {
          const userData = JSON.parse(currentUser);
          console.log('AuthContext: Using cached user data for instant loading:', userData);
          setUser(userData);
          setLoading(false);
          
          // Validate in background without blocking UI
          setTimeout(async () => {
            try {
              const response = await authService.getCurrentUser();
              if (response) {
                console.log('AuthContext: Background validation successful, updating cache');
                localStorage.setItem('currentUser', JSON.stringify(response));
                localStorage.setItem('lastTokenValidation', Date.now().toString());
                setUser(response);
              }
            } catch (error: any) {
              console.log('AuthContext: Background validation failed, but keeping cached user');
              // Only clear session on security breaches or 401 errors
              if (error.response?.status === 403 && error.response?.data?.securityAlert) {
                localStorage.removeItem('accessToken');
                localStorage.removeItem('currentUser');
                localStorage.removeItem('lastTokenValidation');
                setUser(null);
                browserSessionManager.reportCrossBrowserDetection(error.response.data.details);
                browserSessionManager.logoutAllTabs(error.response.data.details.reason);
              } else if (error.response?.status === 401) {
                localStorage.removeItem('accessToken');
                localStorage.removeItem('currentUser');
                localStorage.removeItem('lastTokenValidation');
                setUser(null);
              }
            }
          }, 100);
          
          return;
        } catch (error) {
          console.error('AuthContext: Failed to parse cached user data');
          localStorage.removeItem('currentUser');
          localStorage.removeItem('lastTokenValidation');
        }
      }

      // If no cached data, validate with server
      console.log('AuthContext: No cached data, validating with server...');
      try {
        const response = await authService.getCurrentUser();
        if (response) {
          console.log('AuthContext: Token valid, setting user:', response);
          setUser(response);
          
          // Store user data and validation timestamp
          localStorage.setItem('currentUser', JSON.stringify(response));
          localStorage.setItem('lastTokenValidation', Date.now().toString());
          
          // Sync token across all tabs in same browser
          browserSessionManager.syncTokenAcrossTabs(token);
        } else {
          console.log('AuthContext: No user data returned from server');
          localStorage.removeItem('accessToken');
          localStorage.removeItem('currentUser');
          localStorage.removeItem('lastTokenValidation');
          setUser(null);
        }
      } catch (error: any) {
        console.error('AuthContext: Token validation failed:', error);
        
        // Only clear session on security breaches or 401 errors
        if (error.response?.status === 403 && error.response?.data?.securityAlert) {
          console.log('AuthContext: Cross-browser/IP access detected during initialization');
          localStorage.removeItem('accessToken');
          localStorage.removeItem('currentUser');
          localStorage.removeItem('lastTokenValidation');
          setUser(null);
          browserSessionManager.reportCrossBrowserDetection(error.response.data.details);
          browserSessionManager.logoutAllTabs(error.response.data.details.reason);
        } else if (error.response?.status === 401) {
          console.log('AuthContext: Token expired or invalid, clearing session');
          localStorage.removeItem('accessToken');
          localStorage.removeItem('currentUser');
          localStorage.removeItem('lastTokenValidation');
          setUser(null);
        } else {
          console.log('AuthContext: Network error during validation, user will remain logged out');
          setUser(null);
        }
      } finally {
        setLoading(false);
      }
    };

    initializeAuth();
  }, []);

  // Tab synchronization for same-browser token sharing
  useEffect(() => {
    const handleStorageChange = async (e: StorageEvent) => {
      // Handle token updates from other tabs in same browser
      if (e.key === 'accessToken') {
        if (e.newValue && !user) {
          // Token added by another tab - validate and set user
          console.log(' Token added by another tab, validating...');
          
          try {
            const response = await authService.getCurrentUser();
            if (response) {
              console.log('AuthContext: Token from other tab valid, setting user:', response);
              setUser(response);
            }
          } catch (error: any) {
            console.error(' Token from other tab invalid:', error);
            
            // Handle cross-browser/cross-IP detection
            if (error.response?.status === 403 && error.response?.data?.securityAlert) {
              browserSessionManager.reportCrossBrowserDetection(error.response.data.details);
              browserSessionManager.logoutAllTabs(error.response.data.details.reason);
            } else {
              // Clear invalid token
              localStorage.removeItem('accessToken');
              setUser(null);
            }
          }
        } else if (!e.newValue && user) {
          // Token removed by another tab - logout this tab
          console.log(' Token removed by another tab, logging out');
          setUser(null);
        }
      }
    };

    // Listen for browser session manager events
    const handleBrowserSessionEvent = (event: MessageEvent) => {
      if (event.data.sessionId !== browserSessionManager.getBrowserSessionInfo().sessionId) {
        return; // Ignore messages from different browser sessions
      }

      switch (event.data.type) {
        case 'SECURITY_LOGOUT':
          console.log(' Security logout received from browser session manager');
          localStorage.removeItem('accessToken');
          setUser(null);
          break;
          
        case 'CROSS_BROWSER_DETECTED':
          console.log(' Cross-browser detection alert received');
          localStorage.removeItem('accessToken');
          setUser(null);
          break;
      }
    };

    // INSTANT validation on window focus
    const handleWindowFocus = async () => {
      const token = localStorage.getItem('accessToken');
      if (token && user) {
        console.log(' Validating token on focus...');
        try {
          await authService.getCurrentUser();
        } catch (error: any) {
          console.error(' TOKEN VALIDATION FAILED:', error);
          
          // Handle cross-browser/cross-IP detection
          if (error.response?.status === 403 && error.response?.data?.securityAlert) {
            browserSessionManager.reportCrossBrowserDetection(error.response.data.details);
            browserSessionManager.logoutAllTabs(error.response.data.details.reason);
          } else {
            localStorage.removeItem('accessToken');
            setUser(null);
          }
        }
      }
    };

    const browserChannel = new BroadcastChannel('browser-session-sync');
    browserChannel.addEventListener('message', handleBrowserSessionEvent);
    
    window.addEventListener('storage', handleStorageChange);
    window.addEventListener('focus', handleWindowFocus);
    
    return () => {
      window.removeEventListener('storage', handleStorageChange);
      window.removeEventListener('focus', handleWindowFocus);
      browserChannel.removeEventListener('message', handleBrowserSessionEvent);
      browserChannel.close();
    };
  }, [user]);

  const value: AuthContextType = {
    user,
    loading,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};