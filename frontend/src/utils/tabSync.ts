// Cross-tab session synchronization utility
export class TabSyncManager {
  private channel: BroadcastChannel;
  private storageKey = 'auth_sync';

  constructor() {
    // BroadcastChannel for modern browsers
    this.channel = new BroadcastChannel('auth_sync');
    this.setupListeners();
  }

  private setupListeners() {
    // Listen for messages from other tabs
    this.channel.addEventListener('message', (event) => {
      const { type, data } = event.data;
      
      switch (type) {
        case 'LOGIN':
          this.handleCrossTabLogin(data);
          break;
        case 'LOGOUT':
          this.handleCrossTabLogout();
          break;
        case 'TOKEN_REFRESH':
          this.handleCrossTabTokenRefresh(data);
          break;
      }
    });

    // Fallback: localStorage events for older browsers
    window.addEventListener('storage', (event) => {
      if (event.key === this.storageKey && event.newValue) {
        const data = JSON.parse(event.newValue);
        this.handleStorageSync(data);
      }
    });
  }

  // Broadcast login to other tabs
  broadcastLogin(user: any, token: string) {
    const message = {
      type: 'LOGIN',
      data: { user, token, timestamp: Date.now() }
    };
    
    this.channel.postMessage(message);
    localStorage.setItem(this.storageKey, JSON.stringify(message));
  }

  // Broadcast logout to other tabs
  broadcastLogout() {
    const message = {
      type: 'LOGOUT',
      data: { timestamp: Date.now() }
    };
    
    this.channel.postMessage(message);
    localStorage.setItem(this.storageKey, JSON.stringify(message));
  }

  // Broadcast token refresh to other tabs
  broadcastTokenRefresh(token: string) {
    const message = {
      type: 'TOKEN_REFRESH',
      data: { token, timestamp: Date.now() }
    };
    
    this.channel.postMessage(message);
    localStorage.setItem(this.storageKey, JSON.stringify(message));
  }

  private handleCrossTabLogin(data: any) {
    // Update current tab's auth state
    localStorage.setItem('accessToken', data.token);
    // Trigger auth context update
    window.dispatchEvent(new CustomEvent('auth:login', { detail: data }));
  }

  private handleCrossTabLogout() {
    // Clear current tab's auth state
    localStorage.removeItem('accessToken');
    // Trigger auth context update
    window.dispatchEvent(new CustomEvent('auth:logout'));
  }

  private handleCrossTabTokenRefresh(data: any) {
    // Update current tab's token
    localStorage.setItem('accessToken', data.token);
    // Trigger auth context update
    window.dispatchEvent(new CustomEvent('auth:token-refresh', { detail: data }));
  }

  private handleStorageSync(data: any) {
    // Handle localStorage events (fallback for older browsers)
    switch (data.type) {
      case 'LOGIN':
        this.handleCrossTabLogin(data.data);
        break;
      case 'LOGOUT':
        this.handleCrossTabLogout();
        break;
      case 'TOKEN_REFRESH':
        this.handleCrossTabTokenRefresh(data.data);
        break;
    }
  }

  // Cleanup
  destroy() {
    this.channel.close();
    window.removeEventListener('storage', this.handleStorageSync);
  }
}

export const tabSync = new TabSyncManager();
