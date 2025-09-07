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
      const url = `${process.env.REACT_APP_API_URL || 'http://localhost:5000'}/security/stream`;
      sseRef.current = new EventSource(url, { withCredentials: true });

      sseRef.current.onmessage = (evt) => {
        try {
          const payload = JSON.parse(evt.data);
          if (payload?.type === 'SECURITY_ALERT') setSecurityAlert(true);
        } catch {}
      };
      
      sseRef.current.addEventListener('SECURITY_ALERT', (evt: MessageEvent) => {
        setSecurityAlert(true);
      });
      
      sseRef.current.onerror = () => {
        // Optional: retry/backoff or silently ignore; browser auto-reconnects
      };
    }

    return () => {
      unsub();
      sseRef.current?.close();
    };
  }, [setSecurityAlert, user]);

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
      <AuthProvider>
        <Router>
          <AppContent />
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
};

export default App;
