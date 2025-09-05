import React, { useState } from 'react';
import { Form, Field } from 'react-final-form';
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  Alert,
  CircularProgress,
} from '@mui/material';
import { LoginFormData } from '../types';
import { useAuth } from '../contexts/AuthContext';

interface LoginFormProps {
  onSuccess?: () => void;
}

const validate = (values: LoginFormData) => {
  const errors: Partial<LoginFormData> = {};
  
  if (!values.username) {
    errors.username = 'Username is required';
  } else if (values.username.length < 3) {
    errors.username = 'Username must be at least 3 characters';
  }
  
  if (!values.password) {
    errors.password = 'Password is required';
  } else if (values.password.length < 6) {
    errors.password = 'Password must be at least 6 characters';
  }
  
  return errors;
};

const LoginForm: React.FC<LoginFormProps> = ({ onSuccess }) => {
  const { login, loading } = useAuth();
  const [error, setError] = useState<string>('');

  const handleSubmit = async (values: LoginFormData) => {
    setError('');
    try {
      const response = await login(values.username, values.password);
      if (response.success) {
        onSuccess?.();
      } else {
        setError(response.message || 'Invalid username or password');
      }
    } catch (err) {
      setError('Login failed. Please try again.');
    }
  };

  return (
    <Box
      display="flex"
      justifyContent="center"
      alignItems="center"
      minHeight="100vh"
      bgcolor="background.default"
    >
      <Paper elevation={3} sx={{ p: 4, maxWidth: 400, width: '100%' }}>
        <Typography variant="h4" component="h1" gutterBottom align="center">
          Login
        </Typography>
        
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Form
          onSubmit={handleSubmit}
          validate={validate}
          render={({ handleSubmit, submitting, pristine, invalid }) => (
            <Box component="form" onSubmit={handleSubmit} noValidate>
              <Field name="username">
                {({ input, meta }) => (
                  <TextField
                    {...input}
                    fullWidth
                    margin="normal"
                    label="Username"
                    variant="outlined"
                    error={meta.error && meta.touched}
                    helperText={meta.error && meta.touched ? meta.error : ''}
                    disabled={loading}
                  />
                )}
              </Field>

              <Field name="password">
                {({ input, meta }) => (
                  <TextField
                    {...input}
                    fullWidth
                    margin="normal"
                    label="Password"
                    type="password"
                    variant="outlined"
                    error={meta.error && meta.touched}
                    helperText={meta.error && meta.touched ? meta.error : ''}
                    disabled={loading}
                  />
                )}
              </Field>

              <Button
                type="submit"
                fullWidth
                variant="contained"
                sx={{ mt: 3, mb: 2 }}
                disabled={submitting || pristine || invalid || loading}
                startIcon={loading ? <CircularProgress size={20} /> : null}
              >
                {loading ? 'Signing In...' : 'Sign In'}
              </Button>
            </Box>
          )}
        />
      </Paper>
    </Box>
  );
};

export default LoginForm;
