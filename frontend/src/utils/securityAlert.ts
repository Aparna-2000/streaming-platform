// Custom security alert without browser prefix
export const showSecurityAlert = (message: string): Promise<void> => {
  return new Promise((resolve) => {
    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.7);
      z-index: 10000;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    // Create modal dialog
    const modal = document.createElement('div');
    modal.style.cssText = `
      background: white;
      border-radius: 8px;
      padding: 24px;
      max-width: 400px;
      margin: 20px;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
      text-align: center;
    `;

    // Create message
    const messageEl = document.createElement('div');
    messageEl.style.cssText = `
      font-size: 16px;
      line-height: 1.5;
      margin-bottom: 20px;
      color: #333;
    `;
    messageEl.textContent = message;

    // Create OK button
    const button = document.createElement('button');
    button.textContent = 'OK';
    button.style.cssText = `
      background: #1976d2;
      color: white;
      border: none;
      border-radius: 4px;
      padding: 10px 24px;
      font-size: 14px;
      cursor: pointer;
      font-weight: 500;
    `;

    button.onclick = () => {
      document.body.removeChild(overlay);
      resolve();
    };

    // Assemble modal
    modal.appendChild(messageEl);
    modal.appendChild(button);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Focus the button
    button.focus();
  });
};
