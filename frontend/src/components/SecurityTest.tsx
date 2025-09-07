import React from 'react';
import { tabSync } from '../utils/tabSync';
import { showSecurityAlert } from '../utils/securityAlert';

const SecurityTest: React.FC = () => {
  const testSecurityAlert = async () => {
    console.log('Testing security alert...');
    
    // Simulate security breach response
    await showSecurityAlert('🚨 SECURITY ALERT: Suspicious activity detected on your account. All sessions have been terminated for your protection. Please log in again.');
    
    // Clear token and broadcast logout
    localStorage.removeItem('accessToken');
    tabSync.broadcastLogout(true);
    
    // Force redirect
    setTimeout(() => {
      window.location.replace('/login');
    }, 100);
  };

  const testCrossTabLogout = () => {
    console.log('Testing cross-tab logout...');
    
    // Directly trigger cross-tab logout event
    window.dispatchEvent(new CustomEvent('auth:logout', { 
      detail: { securityAlert: true, timestamp: Date.now() }
    }));
  };

  return (
    <div style={{ padding: '20px', border: '1px solid red', margin: '20px' }}>
      <h3>Security Test Panel</h3>
      <button onClick={testSecurityAlert} style={{ margin: '10px', padding: '10px' }}>
        Test Security Alert
      </button>
      <button onClick={testCrossTabLogout} style={{ margin: '10px', padding: '10px' }}>
        Test Cross-Tab Logout
      </button>
    </div>
  );
};

export default SecurityTest;
