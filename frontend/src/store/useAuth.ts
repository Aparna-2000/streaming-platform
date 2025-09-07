import { create } from 'zustand';

type State = {
  isSecurityAlert: boolean;
  setSecurityAlert: (v: boolean) => void;
  clearAuth: () => void; // clear tokens/local state
};

export const useAuth = create<State>()((set) => ({
  isSecurityAlert: false,
  setSecurityAlert: (v: boolean) => set({ isSecurityAlert: v }),
  clearAuth: () => {
    // Clear any local tokens if you store them (you're on HttpOnly cookies mostly)
    localStorage.removeItem('accessToken'); // if you mirrored it
    sessionStorage.clear();
  },
}));
