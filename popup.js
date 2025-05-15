/**
 * Popup script for Leakin
 * A powerful credential scanner for the web
 */

document.addEventListener('DOMContentLoaded', () => {
  // Tab navigation
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Remove active class from all tabs and contents
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      
      // Add active class to clicked tab and corresponding content
      const tabName = tab.getAttribute('data-tab');
      tab.classList.add('active');
      document.getElementById(tabName).classList.add('active');
    });
  });
  
  // Buttons
  const executeButton = document.getElementById('executeButton');
  const scanStatus = document.getElementById('scanStatus');
  
  // Console logging for developers
  console.log('Extension popup initialized');
  console.log('Extension version: "1.0.1"');
  
  // Execute scan button
  executeButton.addEventListener('click', () => {
    scanStatus.textContent = 'Refreshing page and scanning...';
    executeButton.disabled = true;
    
    // Execute the bookmarklet in the current tab
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      if (tabs && tabs[0]) {
        // First refresh the page
        chrome.tabs.reload(tabs[0].id, {}, () => {
          // Wait a bit for the page to load before scanning
          setTimeout(() => {
            chrome.tabs.sendMessage(tabs[0].id, {
              action: "execute", 
              settings: {
                scanInlineScripts: true,
                scanExternalScripts: true,
                scanWindowObjects: true,
                showPopupOnScan: true
              }
            }, (response) => {
              if (chrome.runtime.lastError) {
                console.error(chrome.runtime.lastError);
                scanStatus.textContent = 'Error: Content script not ready. Please try again.';
              } else {
                scanStatus.textContent = 'Scan complete!';
              }
              executeButton.disabled = false;
            });
          }, 1500); // Give the page 1.5 seconds to load
        });
      } else {
        scanStatus.textContent = 'Error: No active tab found';
        executeButton.disabled = false;
      }
    });
  });
});
