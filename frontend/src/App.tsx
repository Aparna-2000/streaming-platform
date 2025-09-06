import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Navigation from './components/Navigation';
import LoginForm from './components/LoginForm';
import StreamingDashboard from './components/StreamingDashboard';

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

  if (loading) {
    return <div>Loading...</div>;
  }

  return user ? <>{children}</> : <Navigate to="/login" />;
};

const AppContent: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();

  console.log('AppContent: Current user state:', user);

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
