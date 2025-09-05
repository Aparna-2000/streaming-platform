export interface User {
  id: number;
  username: string;
  email: string;
}

export interface LoginFormData {
  username: string;
  password: string;
}

export interface WeatherData {
  location: string;
  current: {
    temperature: number;
    humidity: number;
    description: string;
    icon: string;
  };
  forecast: ForecastDay[];
}

export interface ForecastDay {
  date: string;
  temperature: {
    min: number;
    max: number;
  };
  description: string;
  icon: string;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
}

export interface LoginResponse {
  success: boolean;
  message?: string;
}

export interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => Promise<LoginResponse>;
  logout: () => Promise<void>;
  loading: boolean;
  checkAuthStatus?: () => Promise<void>; // Made optional
}