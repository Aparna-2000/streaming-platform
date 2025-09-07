import React, { useEffect, useRef, useCallback } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Navigation from './components/Navigation';
import LoginForm from './components/LoginForm';
import StreamingDashboard from './components/StreamingDashboard';
import SecurityAlertModal from './components/SecurityAlertModal';
import { useAuth as useSecurityAuth } from './store/useAuth';
import { subscribeSecurityAlert } from './utils/securityBus';

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
  const { user } = useAuth();
  const navigate = useNavigate();
  const { isSecurityAlert, setSecurityAlert, clearAuth } = useSecurityAuth();
  const sseRef = useRef<EventSource | null>(null);

  console.log('AppContent: Current user state:', user);

  // When alert is confirmed, log out and redirect
  const handleSecurityConfirm = useCallback(async () => {
    try {
      await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:5000'}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch {}
    clearAuth();
    setSecurityAlert(false);
    navigate('/login', { replace: true });
  }, [clearAuth, navigate, setSecurityAlert]);

  useEffect(() => {
    // 1) Listen to multi-tab broadcast
    const unsub = subscribeSecurityAlert(() => setSecurityAlert(true));

    // 2) Open SSE to receive server-pushed security alerts (only if authenticated)
    if (user) {
      const token = localStorage.getItem('accessToken');
      if (token) {
        const url = `${process.env.REACT_APP_API_URL || 'http://localhost:5000'}/security/stream?token=${encodeURIComponent(token)}`;
        console.log(`🔗 SSE: Connecting to ${url} for user ${user.id}`);
        sseRef.current = new EventSource(url);

        sseRef.current.onopen = () => {
          console.log('🔗 SSE: Connection opened successfully');
        };

        sseRef.current.onmessage = (evt) => {
          console.log('🚨 SSE: Received message:', evt.data);
          try {
            const payload = JSON.parse(evt.data);
            console.log('🚨 SSE: Parsed payload:', payload);
            if (payload?.type === 'SECURITY_ALERT') {
              console.log('🚨 SSE: Security alert detected, forcing automatic logout');
              // Immediately clear tokens and force logout
              localStorage.removeItem('accessToken');
              clearAuth();
              setSecurityAlert(true);
              // Auto-redirect after showing alert briefly
              setTimeout(() => {
                setSecurityAlert(false);
                navigate('/login', { replace: true });
              }, 3000); // Show alert for 3 seconds then redirect
            }
          } catch (error) {
            console.error('🚨 SSE: Failed to parse message:', error);
          }
        };
        
        // Listen for named SECURITY_ALERT events
        sseRef.current.addEventListener('SECURITY_ALERT', (evt: MessageEvent) => {
          console.log('🚨 SSE: Received SECURITY_ALERT event:', evt.data);
          try {
            const payload = JSON.parse(evt.data);
            console.log('🚨 SSE: Security alert payload:', payload);
            // Immediately clear tokens and force logout
            localStorage.removeItem('accessToken');
            clearAuth();
            setSecurityAlert(true);
            // Auto-redirect after showing alert briefly
            setTimeout(() => {
              setSecurityAlert(false);
              navigate('/login', { replace: true });
            }, 3000); // Show alert for 3 seconds then redirect
          } catch (error) {
            console.error('🚨 SSE: Failed to parse SECURITY_ALERT event:', error);
            // Even if parsing fails, force logout for security
            localStorage.removeItem('accessToken');
            clearAuth();
            setSecurityAlert(true);
            setTimeout(() => {
              setSecurityAlert(false);
              navigate('/login', { replace: true });
            }, 3000);
          }
        });

        // Listen for ping events
        sseRef.current.addEventListener('ping', (evt: MessageEvent) => {
          console.log('🔗 SSE: Received ping:', evt.data);
        });
        
        sseRef.current.onerror = (error) => {
          console.error('🚨 SSE: Connection error:', error);
          // Optional: retry/backoff or silently ignore; browser auto-reconnects
        };
      }
    }

    return () => {
      unsub();
      if (sseRef.current) {
        console.log('🔗 SSE: Closing connection');
        sseRef.current.close();
      }
    };
  }, [setSecurityAlert, user, navigate, clearAuth]);

  const handleLoginSuccess = () => {
    console.log('App: handleLoginSuccess called, navigating to dashboard');
    // Use React Router navigation instead of window.location to avoid page reload
    navigate('/dashboard');
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      {user && <Navigation />}
      <Routes>
        <Route
          path="/login"
          element={
            user ? (
              <Navigate to="/dashboard" />
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
          element={<Navigate to={user ? "/dashboard" : "/login"} />}
        />
      </Routes>
      <SecurityAlertModal open={isSecurityAlert} onConfirm={handleSecurityConfirm} />
    </Box>
  );
};

const App: React.FC = () => {
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
