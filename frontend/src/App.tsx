import React, { useEffect, useRef, useCallback } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Navigation from './components/Navigation';
import LoginForm from './components/LoginForm';
import StreamingDashboard from './components/StreamingDashboard';
import SecurityAlertModal from './components/SecurityAlertModal';
import { useAuth as useSecurityAuth } from './store/useAuth';
import { subscribeSecurityAlert } from './utils/securityBus';
import { browserSessionManager } from './utils/browserSessionManager';
import api from './services/api'; // Assuming you have an api instance

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, loading } = useAuth();

  console.log('ProtectedRoute: loading =', loading, 'user =', user);

  if (loading) {
    return <div>Loading...</div>;
  }

  return user ? <>{children}</> : <Navigate to="/login" />;
};

const AppContent: React.FC = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const { isSecurityAlert, setSecurityAlert, clearAuth, setAccessToken, setUser } = useSecurityAuth();
  const sseRef = useRef<EventSource | null>(null);

  console.log('AppContent: Current user state:', user, 'loading:', loading);

  // When alert is confirmed, log out and redirect
  const handleSecurityConfirm = useCallback(async () => {
    try {
      await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:3001'}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch {}
    clearAuth();
    setSecurityAlert(false);
    navigate('/login', { replace: true });
  }, [clearAuth, navigate, setSecurityAlert]);

  const handleSecurityAlert = useCallback(() => {
    setSecurityAlert(true);
    setTimeout(() => {
      handleSecurityConfirm();
    }, 3000); // Show alert for 3 seconds then redirect
  }, [handleSecurityConfirm, setSecurityAlert]);

  useEffect(() => {
    // Automatic login detection on app startup
    const attemptAutoLogin = async () => {
      const storedToken = localStorage.getItem('accessToken');
      const storedUser = localStorage.getItem('currentUser');
      
      if (storedToken && storedUser && !user) {
        try {
          console.log('🔄 Attempting automatic login with stored token...');
          
          // Parse stored user data
          const userData = JSON.parse(storedUser);
          
          // Validate token by making a test API call
          const response = await api.get('/auth/me');
          
          if (response.data.success && response.data.data) {
            console.log('✅ Auto-login successful');
            
            // Update auth states
            setAccessToken(storedToken);
            setUser(userData);
            
            // Navigate to dashboard if on login page
            if (location.pathname === '/login') {
              navigate('/dashboard', { replace: true });
            }
          }
        } catch (error: any) {
          console.log('❌ Auto-login failed, clearing stored data:', error.response?.status);
          
          // Clear invalid tokens
          localStorage.removeItem('accessToken');
          localStorage.removeItem('currentUser');
          clearAuth();
          
          // Navigate to login if not already there
          if (location.pathname !== '/login') {
            navigate('/login', { replace: true });
          }
        }
      }
    };
    
    // Only attempt auto-login if not already logged in and not loading
    if (!loading && !user) {
      attemptAutoLogin();
    }
  }, [loading, user, setAccessToken, setUser, clearAuth, navigate, location.pathname]);

  useEffect(() => {
    // 1) Listen to multi-tab broadcast
    const unsub = subscribeSecurityAlert(() => {
      console.log('🚨 App: Security alert received from tab sync');
      // Show immediate popup for cross-tab security alerts
      alert('🚨 SECURITY ALERT: Cross-browser access detected! All sessions terminated for security.');
      setSecurityAlert(true);
    });

    // 2) Open SSE to receive server-pushed security alerts (only if authenticated)
    if (user) {
      const accessToken = localStorage.getItem('accessToken');
      const url = `${process.env.REACT_APP_API_URL || 'http://localhost:3001'}/security/stream`;
      console.log(`🔗 SSE: Connecting to ${url} for user ${user.id}`);
      
      // Create EventSource with access token as query parameter
      sseRef.current = new EventSource(url, {
        withCredentials: true,
      });

      sseRef.current.onopen = () => {
        console.log('🔗 SSE: Connection opened successfully for user', user.id);
      };

      sseRef.current.onmessage = (evt) => {
        console.log('🚨 SSE: Received message:', evt.data);
        try {
          const data = JSON.parse(evt.data);
          console.log('🚨 SSE: Parsed security event:', data);
          
          if (data.type === 'SECURITY_ALERT') {
            console.log('🚨 SSE: Security alert received:', data.reason);
            
            // Show different alerts based on security event type
            let alertMessage = '🚨 SECURITY ALERT: ';
            
            switch (data.reason) {
              case 'CROSS_BROWSER_LOGIN_ATTEMPT':
                alertMessage += `New login detected from ${data.newDevice || 'different browser'} at IP ${data.newIP || 'different location'}! All your sessions are being terminated for security.`;
                break;
              case 'CROSS_BROWSER_IP_VIOLATION':
                alertMessage += 'Your account is being accessed from a different browser or IP address! All sessions terminated for security.';
                break;
              case 'DUPLICATE_TOKEN_USAGE':
                alertMessage += 'Your account is being accessed simultaneously from multiple locations! All sessions terminated for security.';
                break;
              default:
                alertMessage += data.message || 'Suspicious activity detected on your account! All sessions terminated for security.';
            }
            
            // IMMEDIATE security alert popup - this must show first
            console.log('🚨 SSE: Showing security alert popup:', alertMessage);
            alert(alertMessage);
            console.log('🚨 SSE: Security alert popup shown');
            
            // Trigger security cleanup and logout AFTER popup
            console.log('🚨 SSE: Triggering security logout...');
            localStorage.setItem('securityBreach', 'true');
            localStorage.setItem('securityReason', data.reason);
            
            // Broadcast to all tabs
            const channel = new BroadcastChannel('security-channel');
            channel.postMessage({ 
              type: 'SECURITY_BREACH', 
              reason: data.reason,
              timestamp: new Date().toISOString()
            });
            
            // Force logout and redirect
            handleSecurityAlert();
          }
        } catch (error) {
          console.error('🚨 SSE: Failed to parse security event:', error);
        }
      };
      
      // Listen for named SECURITY_ALERT events
      sseRef.current.addEventListener('SECURITY_ALERT', (evt: MessageEvent) => {
        console.log('🚨 SSE: Received SECURITY_ALERT event:', evt.data);
        try {
          const payload = JSON.parse(evt.data);
          console.log('🚨 SSE: Parsed SECURITY_ALERT payload:', payload);
          
          // Show immediate security popup
          const alertMessage = `🚨 SECURITY ALERT: ${payload.message || 'Suspicious activity detected on your account! All sessions terminated for security.'}`;
          alert(alertMessage);
          
          // Force logout
          localStorage.removeItem('accessToken');
          localStorage.removeItem('currentUser');
          clearAuth();
          handleSecurityAlert();
        } catch (error) {
          console.error('🚨 SSE: Failed to parse SECURITY_ALERT event:', error);
          // Even if parsing fails, force logout for security
          localStorage.removeItem('accessToken');
          localStorage.removeItem('currentUser');
          clearAuth();
          handleSecurityAlert();
        }
      });

      sseRef.current.onerror = (error) => {
        console.error('🔗 SSE: Connection error:', error);
        console.log('🚨 SSE: Connection state:', sseRef.current?.readyState);
      };
    }

    return () => {
      unsub();
      if (sseRef.current) {
        console.log('🔗 SSE: Closing connection');
        sseRef.current.close();
      }
    };
  }, [setSecurityAlert, user, navigate, clearAuth, handleSecurityAlert]);

  const handleLoginSuccess = () => {
    console.log('App: handleLoginSuccess called, navigating to dashboard');
    // Use React Router navigation instead of window.location to avoid page reload
    navigate('/dashboard');
  };

  useEffect(() => {
    const handleGlobalError = (event: ErrorEvent) => {
      console.log('🌐 Global error caught:', event);
    };

    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      console.log('🌐 Unhandled promise rejection:', event.reason);
      
      // Check if this is a security alert that wasn't handled
      if (event.reason?.response?.status === 403 && 
          event.reason?.response?.data?.securityAlert) {
        
        console.log('🚨 Global handler: Security alert detected');
        const alertMessage = '🚨 SECURITY ALERT: Unauthorized access detected! All sessions terminated for security.';
        
        setTimeout(() => {
          alert(alertMessage);
          console.log('🚨 Global handler: Security alert popup displayed');
        }, 100);
        
        try {
          alert(alertMessage);
          console.log('🚨 Global handler: Immediate security alert displayed');
        } catch (e) {
          console.error('🚨 Global handler: Failed to show alert:', e);
        }
        
        // Prevent default handling
        event.preventDefault();
      }
    };

    window.addEventListener('error', handleGlobalError);
    window.addEventListener('unhandledrejection', handleUnhandledRejection);

    return () => {
      window.removeEventListener('error', handleGlobalError);
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
    };
  }, []);

  useEffect(() => {
    // Automatic cross-tab logout synchronization
    const broadcastChannel = new BroadcastChannel('auth-sync');
    
    // Listen for logout events from other tabs
    const handleBroadcastMessage = (event: MessageEvent) => {
      console.log('📡 Cross-tab message received:', event.data);
      
      if (event.data.type === 'SECURITY_LOGOUT') {
        console.log('🚨 Cross-tab security logout triggered');
        
        // Show security alert in this tab
        const alertMessage = event.data.message || '🚨 SECURITY ALERT: Session terminated due to suspicious activity detected in another tab!';
        
        setTimeout(() => {
          alert(alertMessage);
          console.log('🚨 Cross-tab security alert displayed');
        }, 100);
        
        // Force logout in this tab
        clearAuth();
        navigate('/login', { replace: true });
      } else if (event.data.type === 'LOGIN') {
        console.log('🔑 Cross-tab login sync triggered');
        
        // Update auth state in this tab
        if (event.data.accessToken && event.data.user) {
          localStorage.setItem('accessToken', event.data.accessToken);
          localStorage.setItem('currentUser', JSON.stringify(event.data.user));
          
          // Trigger auth context update
          setAccessToken(event.data.accessToken);
          setUser(event.data.user);
          
          // Navigate to dashboard if currently on login page
          if (location.pathname === '/login') {
            navigate('/dashboard', { replace: true });
          }
          
          console.log('🔑 Cross-tab login sync completed');
        }
      }
    };
    
    broadcastChannel.addEventListener('message', handleBroadcastMessage);
    
    // Fallback: localStorage event for older browsers
    const handleStorageChange = (event: StorageEvent) => {
      console.log('💾 Storage change detected:', event.key, event.newValue);
      
      if (event.key === 'auth-logout-sync' && event.newValue) {
        const logoutData = JSON.parse(event.newValue);
        console.log('🚪 Storage-based logout sync:', logoutData);
        
        if (logoutData.type === 'SECURITY_LOGOUT') {
          const alertMessage = logoutData.message || '🚨 SECURITY ALERT: Session terminated due to suspicious activity!';
          
          setTimeout(() => {
            alert(alertMessage);
            console.log('🚨 Storage-based security alert displayed');
          }, 100);
          
          // Force logout in this tab
          clearAuth();
          navigate('/login', { replace: true });
        }
        
        // Clean up the storage event
        setTimeout(() => {
          localStorage.removeItem('auth-logout-sync');
        }, 1000);
      } else if (event.key === 'auth-login-sync' && event.newValue) {
        const loginData = JSON.parse(event.newValue);
        console.log('🔑 Storage-based login sync:', loginData);
        
        if (loginData.type === 'LOGIN' && loginData.accessToken && loginData.user) {
          // Update auth state in this tab
          setAccessToken(loginData.accessToken);
          setUser(loginData.user);
          
          // Navigate to dashboard if currently on login page
          if (location.pathname === '/login') {
            navigate('/dashboard', { replace: true });
          }
          
          console.log('🔑 Storage-based login sync completed');
        }
        
        // Clean up the storage event
        setTimeout(() => {
          localStorage.removeItem('auth-login-sync');
        }, 1000);
      }
    };
    
    window.addEventListener('storage', handleStorageChange);
    
    // Cleanup
    return () => {
      broadcastChannel.removeEventListener('message', handleBroadcastMessage);
      broadcastChannel.close();
      window.removeEventListener('storage', handleStorageChange);
    };
  }, [clearAuth, navigate, setAccessToken, setUser, location.pathname]);

  return (
    <Box sx={{ flexGrow: 1 }}>
      {user && <Navigation />}
      
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
          <div>Loading...</div>
        </Box>
      ) : (
        <Routes>
          <Route
            path="/login"
            element={
              user ? (
                <Navigate to="/dashboard" replace />
              ) : (
                <LoginForm onSuccess={handleLoginSuccess} />
              )
            }
          />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <StreamingDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/"
            element={<Navigate to={user ? "/dashboard" : "/login"} replace />}
          />
        </Routes>
      )}
      <SecurityAlertModal open={isSecurityAlert} onConfirm={handleSecurityConfirm} />
    </Box>
  );
};

const App: React.FC = () => {
  // BROWSER SESSION MANAGEMENT - Allow same browser tabs, block cross-browser/cross-IP
  useEffect(() => {
    // Initialize browser session manager
    const sessionInfo = browserSessionManager.getBrowserSessionInfo();
    console.log('🔗 Browser session initialized:', sessionInfo);

    // VALIDATION - Only validate on security events, not continuously
    const handleCrossBrowserAlert = (event: MessageEvent) => {
      if (event.data.type === 'CROSS_BROWSER_DETECTED') {
        console.log('🚨 Cross-browser access detected, forcing logout');
        browserSessionManager.logoutAllTabs('Cross-browser access detected');
      }
    };

    // Set up browser session communication
    const channel = new BroadcastChannel('browser-session-sync');
    channel.addEventListener('message', handleCrossBrowserAlert);

    return () => {
      channel.removeEventListener('message', handleCrossBrowserAlert);
      channel.close();
    };
  }, []);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router
        future={{
          v7_startTransition: true,
          v7_relativeSplatPath: true
        }}
      >
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </Router>
    </ThemeProvider>
  );
};

export default App;
