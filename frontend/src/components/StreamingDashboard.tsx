import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
} from '@mui/material';
import { PlayArrow, Movie, Tv, TrendingUp } from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

const StreamingDashboard: React.FC = () => {
  const { user } = useAuth();

  const mockContent = [
    { id: 1, title: 'Popular Movie 1', type: 'movie', views: '2.1M' },
    { id: 2, title: 'Trending Series 1', type: 'series', views: '1.8M' },
    { id: 3, title: 'Popular Movie 2', type: 'movie', views: '1.5M' },
    { id: 4, title: 'Trending Series 2', type: 'series', views: '1.2M' },
  ];

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Welcome back, {user?.username}!
      </Typography>
      
      <Typography variant="h6" color="text.secondary" gutterBottom sx={{ mb: 3 }}>
        Streaming Platform Dashboard
      </Typography>

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <Movie color="primary" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography variant="h4">1,234</Typography>
                  <Typography color="text.secondary">Movies</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <Tv color="primary" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography variant="h4">567</Typography>
                  <Typography color="text.secondary">TV Shows</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <PlayArrow color="primary" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography variant="h4">89K</Typography>
                  <Typography color="text.secondary">Active Users</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <TrendingUp color="primary" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography variant="h4">12.5M</Typography>
                  <Typography color="text.secondary">Total Views</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Popular Content */}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h5" gutterBottom>
          Popular Content
        </Typography>
        <Grid container spacing={2}>
          {mockContent.map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.id}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" gap={1} mb={1}>
                    {item.type === 'movie' ? <Movie /> : <Tv />}
                    <Typography variant="subtitle2">
                      {item.type === 'movie' ? 'Movie' : 'Series'}
                    </Typography>
                  </Box>
                  <Typography variant="h6" gutterBottom>
                    {item.title}
                  </Typography>
                  <Typography color="text.secondary" sx={{ mb: 2 }}>
                    {item.views} views
                  </Typography>
                  <Button variant="contained" size="small" startIcon={<PlayArrow />}>
                    Watch Now
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Box>
  );
};

export default StreamingDashboard;
