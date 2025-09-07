import { create } from 'zustand';
import { User } from '../types';

type State = {
  isSecurityAlert: boolean;
  accessToken: string | null;
  user: User | null;
  setSecurityAlert: (v: boolean) => void;
  setAccessToken: (token: string | null) => void;
  setUser: (user: User | null) => void;
  clearAuth: () => void; // clear tokens/local state
};

export const useAuth = create<State>()((set) => ({
  isSecurityAlert: false,
  accessToken: null,
  user: null,
  setSecurityAlert: (v: boolean) => set({ isSecurityAlert: v }),
  setAccessToken: (token: string | null) => set({ accessToken: token }),
  setUser: (user: User | null) => set({ user }),
  clearAuth: () => {
    // Clear any local tokens if you store them (you're on HttpOnly cookies mostly)
    localStorage.removeItem('accessToken'); // if you mirrored it
    localStorage.removeItem('currentUser');
    sessionStorage.clear();
    set({ accessToken: null, user: null, isSecurityAlert: false });
  },
}));
