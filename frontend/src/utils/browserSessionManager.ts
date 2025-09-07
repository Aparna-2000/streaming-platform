// Browser Session Manager - Strict tab-to-tab connection within same browser only
export class BrowserSessionManager {
  private static instance: BrowserSessionManager;
  private sessionId: string;
  private tabId: string;
  private channel: BroadcastChannel;
  private activeTabs: Set<string> = new Set();
  
  private constructor() {
    // Generate unique session ID for this browser instance
    this.sessionId = this.getOrCreateBrowserSessionId();
    this.tabId = this.generateTabId();
    this.channel = new BroadcastChannel('browser-session-sync');
    
    this.setupTabCommunication();
    this.registerTab();
  }
  
  public static getInstance(): BrowserSessionManager {
    if (!BrowserSessionManager.instance) {
      BrowserSessionManager.instance = new BrowserSessionManager();
    }
    return BrowserSessionManager.instance;
  }
  
  private getOrCreateBrowserSessionId(): string {
    // Use sessionStorage to ensure same browser instance
    let sessionId = sessionStorage.getItem('browserSessionId');
    if (!sessionId) {
      sessionId = `browser_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      sessionStorage.setItem('browserSessionId', sessionId);
    }
    return sessionId;
  }
  
  private generateTabId(): string {
    return `tab_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  private setupTabCommunication(): void {
    this.channel.addEventListener('message', (event) => {
      const { type, tabId, sessionId, data } = event.data;
      
      // Only process messages from same browser session
      if (sessionId !== this.sessionId) {
        console.log('🚫 Ignoring message from different browser session');
        return;
      }
      
      switch (type) {
        case 'TAB_REGISTER':
          this.activeTabs.add(tabId);
          console.log(`✅ Tab registered: ${tabId}, Active tabs: ${this.activeTabs.size}`);
          break;
          
        case 'TAB_UNREGISTER':
          this.activeTabs.delete(tabId);
          console.log(`❌ Tab unregistered: ${tabId}, Active tabs: ${this.activeTabs.size}`);
          break;
          
        case 'TOKEN_UPDATE':
          if (tabId !== this.tabId) {
            this.handleTokenUpdate(data.token);
          }
          break;
          
        case 'SECURITY_LOGOUT':
          if (tabId !== this.tabId) {
            this.handleSecurityLogout(data.reason);
          }
          break;
          
        case 'CROSS_BROWSER_DETECTED':
          this.handleCrossBrowserDetection(data);
          break;
      }
    });
    
    // Cleanup on tab close
    window.addEventListener('beforeunload', () => {
      this.unregisterTab();
    });
  }
  
  private registerTab(): void {
    this.activeTabs.add(this.tabId);
    this.broadcastToTabs('TAB_REGISTER', { tabId: this.tabId });
    console.log(`🔗 Tab registered in browser session: ${this.sessionId}`);
  }
  
  private unregisterTab(): void {
    this.broadcastToTabs('TAB_UNREGISTER', { tabId: this.tabId });
    this.activeTabs.delete(this.tabId);
  }
  
  private broadcastToTabs(type: string, data: any): void {
    this.channel.postMessage({
      type,
      tabId: this.tabId,
      sessionId: this.sessionId,
      data,
      timestamp: Date.now()
    });
  }
  
  public syncTokenAcrossTabs(token: string): void {
    // Only sync if token is different from current localStorage value
    const currentToken = localStorage.getItem('accessToken');
    if (currentToken !== token) {
      localStorage.setItem('accessToken', token);
      this.broadcastToTabs('TOKEN_UPDATE', { token });
      console.log(`🔄 Token synced across ${this.activeTabs.size} tabs in browser session`);
    } else {
      console.log('🔄 Token already synced, skipping broadcast');
    }
  }
  
  public logoutAllTabs(reason: string): void {
    // Force logout all tabs in same browser
    localStorage.removeItem('accessToken');
    localStorage.removeItem('currentUser');
    localStorage.removeItem('lastTokenValidation');
    this.broadcastToTabs('SECURITY_LOGOUT', { reason });
    console.log(`🚨 Security logout broadcast to all tabs: ${reason}`);
  }
  
  public reportCrossBrowserDetection(details: any): void {
    // Alert all tabs about cross-browser access attempt
    this.broadcastToTabs('CROSS_BROWSER_DETECTED', details);
    console.log('🚨 Cross-browser access detected, alerting all tabs');
  }
  
  private handleTokenUpdate(token: string): void {
    console.log('🔄 Received token update from another tab');
    localStorage.setItem('accessToken', token);
    // Trigger auth context update
    window.dispatchEvent(new StorageEvent('storage', {
      key: 'accessToken',
      newValue: token,
      storageArea: localStorage
    }));
  }
  
  private handleSecurityLogout(reason: string): void {
    console.log(`🚨 Security logout received from another tab: ${reason}`);
    localStorage.removeItem('accessToken');
    
    // Show security alert
    alert(`🚨 SECURITY ALERT: ${reason}. All tabs in this browser are being logged out.`);
    
    // Force page refresh to login
    window.location.href = '/login';
  }
  
  private handleCrossBrowserDetection(details: any): void {
    console.log('🚨 Cross-browser access attempt detected:', details);
    
    // Show immediate security warning
    alert(`🚨 SECURITY WARNING: Your token was used in a different browser!\n\nExpected: ${details.expectedDevice}\nDetected: ${details.actualDevice}\n\nAll sessions terminated for security.`);
    
    // Force logout this browser
    this.logoutAllTabs('Cross-browser access detected');
  }
  
  public getBrowserSessionInfo() {
    return {
      sessionId: this.sessionId,
      tabId: this.tabId,
      activeTabs: Array.from(this.activeTabs),
      tabCount: this.activeTabs.size
    };
  }
  
  public validateSameBrowserSession(incomingSessionId: string): boolean {
    return this.sessionId === incomingSessionId;
  }
}

// Export singleton instance
export const browserSessionManager = BrowserSessionManager.getInstance();
