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
          this.handleCrossTabLogout(data);
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
  broadcastLogout(securityAlert?: boolean) {
    console.log('🚨 TabSync: Broadcasting logout, securityAlert:', securityAlert);
    const message = {
      type: 'LOGOUT',
      data: { timestamp: Date.now(), securityAlert }
    };
    
    console.log('🚨 TabSync: Logout message:', message);
    this.channel.postMessage(message);
    localStorage.setItem(this.storageKey, JSON.stringify(message));
    
    // Also clear the access token immediately in current tab
    localStorage.removeItem('accessToken');
    console.log('🚨 TabSync: Access token cleared');
    
    // IMPORTANT: BroadcastChannel doesn't send to self, so handle logout in current tab too
    console.log('🚨 TabSync: Handling logout in current tab...');
    this.handleCrossTabLogout(message.data);
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

  private async handleCrossTabLogout(data: any) {
    console.log('🚨 TabSync: handleCrossTabLogout called with data:', data);
    localStorage.removeItem('accessToken');
    console.log('🚨 TabSync: Dispatching auth:logout event with detail:', data);
    window.dispatchEvent(new CustomEvent('auth:logout', { detail: data }));
    console.log('🚨 TabSync: auth:logout event dispatched');
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
        this.handleCrossTabLogout(data.data);
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
