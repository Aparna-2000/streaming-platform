import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  CircularProgress,
  Alert,
  TextField,
  Button,
  Chip,
} from '@mui/material';
import { WbSunny, Cloud, Grain, Opacity } from '@mui/icons-material';
import { WeatherData, ForecastDay } from '../types';
import { weatherService } from '../services/api';

const WeatherDashboard: React.FC = () => {
  const [weatherData, setWeatherData] = useState<WeatherData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [city, setCity] = useState('London');
  const [searchCity, setSearchCity] = useState('London');

  useEffect(() => {
    fetchWeatherData(city);
  }, [city]);

  const fetchWeatherData = async (cityName: string) => {
    setLoading(true);
    setError('');
    try {
      const response = await weatherService.getWeatherData(cityName);
      if (response.success && response.data) {
        setWeatherData(response.data);
      } else {
        setError(response.message || 'Failed to fetch weather data');
      }
    } catch (err) {
      setError('Failed to fetch weather data');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    if (searchCity.trim()) {
      setCity(searchCity.trim());
    }
  };

  const getWeatherIcon = (iconCode: string) => {
    // Simple icon mapping - in a real app, you'd use the actual weather icons
    if (iconCode.includes('sun') || iconCode.includes('clear')) {
      return <WbSunny sx={{ fontSize: 48, color: '#FFA726' }} />;
    } else if (iconCode.includes('cloud')) {
      return <Cloud sx={{ fontSize: 48, color: '#90A4AE' }} />;
    } else if (iconCode.includes('rain')) {
      return <Grain sx={{ fontSize: 48, color: '#42A5F5' }} />;
    }
    return <WbSunny sx={{ fontSize: 48, color: '#FFA726' }} />;
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {error}
      </Alert>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Weather Dashboard
      </Typography>

      {/* Search Bar */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Box display="flex" gap={2} alignItems="center">
          <TextField
            label="City"
            value={searchCity}
            onChange={(e) => setSearchCity(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
            size="small"
            sx={{ flexGrow: 1 }}
          />
          <Button variant="contained" onClick={handleSearch}>
            Search
          </Button>
        </Box>
      </Paper>

      {weatherData && (
        <>
          {/* Current Weather */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h5" gutterBottom>
              Current Weather - {weatherData.location}
            </Typography>
            <Grid container spacing={3} alignItems="center">
              <Grid item xs={12} md={6}>
                <Box display="flex" alignItems="center" gap={2}>
                  {getWeatherIcon(weatherData.current.icon)}
                  <Box>
                    <Typography variant="h3" component="div">
                      {Math.round(weatherData.current.temperature)}°C
                    </Typography>
                    <Typography variant="h6" color="text.secondary">
                      {weatherData.current.description}
                    </Typography>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box display="flex" flexDirection="column" gap={1}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Opacity color="primary" />
                    <Typography>
                      Humidity: {weatherData.current.humidity}%
                    </Typography>
                  </Box>
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* 5-Day Forecast */}
          <Paper sx={{ p: 3 }}>
            <Typography variant="h5" gutterBottom>
              5-Day Forecast
            </Typography>
            <Grid container spacing={2}>
              {weatherData.forecast.map((day: ForecastDay, index: number) => (
                <Grid item xs={12} sm={6} md={2.4} key={index}>
                  <Card>
                    <CardContent sx={{ textAlign: 'center' }}>
                      <Typography variant="subtitle2" gutterBottom>
                        {new Date(day.date).toLocaleDateString('en-US', {
                          weekday: 'short',
                          month: 'short',
                          day: 'numeric',
                        })}
                      </Typography>
                      {getWeatherIcon(day.icon)}
                      <Typography variant="body2" sx={{ mt: 1 }}>
                        {day.description}
                      </Typography>
                      <Box sx={{ mt: 1 }}>
                        <Chip
                          label={`${Math.round(day.temperature.max)}°`}
                          size="small"
                          color="primary"
                          sx={{ mr: 0.5 }}
                        />
                        <Chip
                          label={`${Math.round(day.temperature.min)}°`}
                          size="small"
                          variant="outlined"
                        />
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </>
      )}
    </Box>
  );
};

export default WeatherDashboard;
