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
  const versionDisplay = document.getElementById('versionDisplay');

  // Display extension version
  if (versionDisplay) {
    const manifestData = chrome.runtime.getManifest();
    versionDisplay.textContent = `Version ${manifestData.version}`;
  }
  
  // Console logging for developers
  console.log('Extension popup initialized');
  console.log(`Extension version: "${chrome.runtime.getManifest().version}"`);

  // Settings elements
  const settingsCheckboxes = {
    scanInlineScripts: document.getElementById('scanInlineScripts'),
    scanExternalScripts: document.getElementById('scanExternalScripts'),
    scanWindowObjects: document.getElementById('scanWindowObjects'),
    showPopupOnScan: document.getElementById('showPopupOnScan')
  };

  // Default settings
  const defaultSettings = {
    scanInlineScripts: true,
    scanExternalScripts: true,
    scanWindowObjects: true,
    showPopupOnScan: true
  };

  // Load settings from storage and update checkboxes
  function loadSettings() {
    chrome.storage.sync.get(defaultSettings, (items) => {
      if (chrome.runtime.lastError) {
        console.error("Error loading settings:", chrome.runtime.lastError);
        // Apply defaults if error
        Object.keys(defaultSettings).forEach(key => {
          if (settingsCheckboxes[key]) settingsCheckboxes[key].checked = defaultSettings[key];
        });
        return;
      }
      Object.keys(items).forEach(key => {
        if (settingsCheckboxes[key]) {
          settingsCheckboxes[key].checked = items[key];
        }
      });
    });
  }

  // Save settings to storage
  function saveSettings() {
    let currentSettings = {};
    Object.keys(settingsCheckboxes).forEach(key => {
      if (settingsCheckboxes[key]) {
        currentSettings[key] = settingsCheckboxes[key].checked;
      }
    });
    chrome.storage.sync.set(currentSettings, () => {
      if (chrome.runtime.lastError) {
        console.error("Error saving settings:", chrome.runtime.lastError);
      } else {
        console.log("Settings saved.");
      }
    });
  }

  // Add event listeners to checkboxes to save settings on change
  Object.values(settingsCheckboxes).forEach(checkbox => {
    if (checkbox) {
      checkbox.addEventListener('change', saveSettings);
    }
  });

  // Load settings when popup opens
  loadSettings();

  const resultsContainer = document.getElementById('resultsContainer');
  const clearResultsButton = document.getElementById('clearResultsButton');

  function renderFindings(findings) {
    if (!resultsContainer) return;
    resultsContainer.innerHTML = ''; // Clear previous results

    if (!findings || findings.length === 0) {
      resultsContainer.innerHTML = '<p>No findings from the last scan, or results have been cleared.</p>';
      return;
    }

    const ul = document.createElement('ul');
    ul.style.listStyleType = 'none';
    ul.style.paddingLeft = '0';

    findings.forEach(finding => {
      const li = document.createElement('li');
      li.style.marginBottom = '10px';
      li.style.paddingBottom = '10px';
      li.style.borderBottom = '1px solid #ddd';

      let sourcesHTML = '';
      if (finding.sources && finding.sources.length > 0) {
        sourcesHTML = `<ul>${finding.sources.map(s => `<li><small>${s.length > 60 ? s.substring(0,57) + "..." : s}</small></li>`).join('')}</ul>`;
      } else if (finding.source) { // Fallback for older format if necessary
         sourcesHTML = `<small>${finding.source.length > 60 ? finding.source.substring(0,57) + "..." : finding.source}</small>`;
      }


      li.innerHTML = `
        <strong>Type:</strong> ${finding.pattern} (<span style="color: ${finding.riskLevel === 'CRITICAL' ? 'red' : finding.riskLevel === 'HIGH' ? 'orange' : 'green'};">${finding.riskLevel}</span>)<br>
        <strong>Match:</strong> <code style="word-break:break-all; background-color: #f0f0f0; padding: 2px 4px; border-radius:3px;">${(finding.match || "").length > 100 ? (finding.match || "").substring(0,97)+"..." : (finding.match || "")}</code><br>
        <strong>Found in:</strong> ${sourcesHTML}
        ${finding.description ? `<small><strong>Note:</strong> ${finding.description}</small><br>` : ''}
        ${finding.decoded && finding.decoded.payload ? `<details><summary>Decoded JWT Payload</summary><pre style="font-size:0.8em; max-height:100px; overflow:auto; background:#eee; padding:5px;">${JSON.stringify(finding.decoded.payload, null, 2)}</pre></details>` : ''}
      `;
      ul.appendChild(li);
    });
    resultsContainer.appendChild(ul);
  }

  // Load and display findings when the results tab is shown or popup opens
  function loadAndDisplayFindings() {
    chrome.storage.local.get('lastScanFindings', (data) => {
      if (chrome.runtime.lastError) {
        console.error("Error loading findings:", chrome.runtime.lastError);
        resultsContainer.innerHTML = '<p>Error loading findings.</p>';
        return;
      }
      renderFindings(data.lastScanFindings);
    });
  }

  // Initial load for when popup opens and results tab might be active
  loadAndDisplayFindings();

  // Update results when "Results" tab is clicked
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      if (tab.getAttribute('data-tab') === 'results') {
        loadAndDisplayFindings();
      }
    });
  });

  if (clearResultsButton) {
    clearResultsButton.addEventListener('click', () => {
      chrome.storage.local.remove('lastScanFindings', () => {
        if (chrome.runtime.lastError) {
          console.error("Error clearing findings:", chrome.runtime.lastError);
        } else {
          console.log("Last scan findings cleared.");
          loadAndDisplayFindings(); // Refresh display
        }
      });
    });
  }
  
  // Execute scan button
  executeButton.addEventListener('click', () => {
    scanStatus.textContent = 'Refreshing page and scanning...';
    executeButton.disabled = true;

    // Get current settings from checkboxes to send with the message
    let currentScanSettings = {};
    Object.keys(settingsCheckboxes).forEach(key => {
      if (settingsCheckboxes[key]) {
        currentScanSettings[key] = settingsCheckboxes[key].checked;
      } else {
        // Fallback to default if checkbox somehow not found (should not happen)
        currentScanSettings[key] = defaultSettings[key];
      }
    });
    
    // Execute the bookmarklet in the current tab
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      if (tabs && tabs[0]) {
        const tabId = tabs[0].id;
        // First refresh the page
        chrome.tabs.reload(tabId, {}, () => {
          // Attempt to send the message shortly after reload callback.
          // Content script has logic to queue if not immediately ready.
          // We'll use a short delay to allow the tab to settle from reload.
          setTimeout(() => {
            chrome.tabs.sendMessage(tabId, {
              action: "execute", 
              settings: currentScanSettings // Send current settings
            }, (response) => {
              if (chrome.runtime.lastError) {
                console.error("Error sending message to content script:",chrome.runtime.lastError.message);
                scanStatus.textContent = 'Error: Could not connect to page. Try again after page loads, or on a different page.';
                executeButton.disabled = false;
              } else if (response && response.status === "executed") {
                scanStatus.textContent = `Scan complete! Found ${response.findingsCount} items.`;
                chrome.storage.local.set({lastScanFindings: response.findings || []}, () => {
                  if (chrome.runtime.lastError) console.error("Error saving findings to local storage:", chrome.runtime.lastError);
                  // Optionally, switch to results tab if findings are present
                  if (response.findingsCount > 0) {
                    // document.querySelector('.tab[data-tab="results"]').click(); // Uncomment to auto-switch
                    loadAndDisplayFindings(); // Ensure results tab is updated if already active
                  }
                });
                executeButton.disabled = false;
              } else {
                // Handle other responses or lack of response if content script queues but doesn't confirm execution quickly
                console.log("Scan initiated, content script may be processing.", response);
                // scanStatus.textContent = 'Scan initiated...'; // Keep it on "scanning..."
                // The button will be re-enabled by the response or error handling eventually.
                // If no response comes, user might need to click again.
                // This part depends on how robust the queuing and eventual response from content.js is.
                // For now, we assume content.js will eventually respond or popup will hit runtime.lastError.
              }
            });
          }, 250); // Reduced delay, content script handles queuing.
        });
      } else {
        scanStatus.textContent = 'Error: No active tab found';
        executeButton.disabled = false;
      }
    });
  });
});
