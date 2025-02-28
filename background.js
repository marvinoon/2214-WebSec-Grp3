// Helper function to compare semantic versions.
function isVersionOutdated(current, latest) {
  const currentParts = current.split('.').map(Number);
  const latestParts = latest.split('.').map(Number);
  for (let i = 0; i < Math.max(currentParts.length, latestParts.length); i++) {
    const cur = currentParts[i] || 0;
    const lat = latestParts[i] || 0;
    if (cur < lat) return true;
    if (cur > lat) return false;
  }
  return false;
}

// Generic function to fetch and parse versions
async function fetchLatestVersion(url, regex) {
  try {
    const response = await fetch(url);
    const html = await response.text();
    const match = html.match(regex);
    return match ? match[1] : null;
  } catch (error) {
    console.error(`Error fetching from ${url}:`, error);
    return null;
  }
}

// Fetch latest Nginx version
async function getLatestNginxVersionOfficial() {
  const url = "https://thingproxy.freeboard.io/fetch/https://nginx.org/en/download.html";
  return await fetchLatestVersion(url, /nginx-(\d+\.\d+\.\d+)\.tar\.gz/i);
}

// Fetch latest PHP version
async function getLatestPHPVersionOfficial() {
  const url = "https://thingproxy.freeboard.io/fetch/https://www.php.net/downloads.php";
  return await fetchLatestVersion(url, /php-(\d+\.\d+\.\d+)\.tar\.gz/i);
}

// Generic function to scan for vulnerabilities
async function scanForVulnerability(target, options, payloads, detectionFn) {
  const vulnerabilities = [];
  for (const payload of payloads) {
      try {
          const testUrl = `${target}/?q=${encodeURIComponent(payload)}`;
          const response = await fetch(testUrl);
          const data = await response.text();
          if (detectionFn(data, payload)) {
            vulnerabilities.push(`[+] Vulnerability detected: ${payload}`);
          }
      } catch (error) {
        console.error("Scan error:", error);
      }
  }
  return vulnerabilities;
}

// Reflected XSS scan
async function scanReflectedXSS(target, options) {
  if (!options.xss) return [];
  
  let vulnerabilities = [];
  let xssPayloads = [
    "<div id='xss-test'>XSS</div>",
    "\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>"
  ];

  let scanPromises = xssPayloads.map(payload => {
    let testUrl = `${target}/?q=${encodeURIComponent(payload)}`;
    return fetch(testUrl, { method: "GET" })
      .then(response => response.text())
      .then(data => {
          if (data.includes("xss-test") || data.includes("alert('XSS')")) {
              vulnerabilities.push(`[+] Reflected XSS detected with payload: ${payload}`);
            }
        })
        .catch(error => console.error("XSS scan error:", error));
  });

  // Wait for all payloads to complete scanning
  await Promise.all(scanPromises);

  return vulnerabilities;
}


async function scanStoredXSS(target, options) {
  if (!options.storedXss) return [];

  let vulnerabilities = [];

  // Wrap chrome.tabs.query as a promise for async/await usage
  const queryTabs = () => 
    new Promise((resolve, reject) => {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (chrome.runtime.lastError) return reject(chrome.runtime.lastError);
        resolve(tabs);
      });
    });

  try {
    const tabs = await queryTabs();
    if (tabs.length === 0) return vulnerabilities;
    let activeTabId = tabs[0].id;

    // Execute script to inject XSS payload
    await chrome.scripting.executeScript({
      target: { tabId: activeTabId },
      function: () => {
        let storedPayload = "<div id='xss-test'>XSS</div>";
        let forms = document.forms;
        for (let form of forms) {
          let inputs = form.getElementsByTagName("input");
          for (let input of inputs) {
            input.value = storedPayload;
          }
          form.submit();
        }
      }
    });

    vulnerabilities.push("[+] Stored XSS payload attempted.");

    // ✅ Verify if the XSS payload persists
    await new Promise(resolve => setTimeout(resolve, 3000)); // Wait for the payload to take effect

    const response = await fetch(target);
    const data = await response.text();

    if (data.includes("xss-test")) {      
      vulnerabilities.push("[!] Stored XSS successfully injected and persisted.");
    }

  } catch (error) {
    console.error("Stored XSS scan error:", error);
    vulnerabilities.push("❌ Error during Stored XSS scan.");
  }

  return vulnerabilities;
}



// Local File Inclusion (LFI) scan
async function scanLFI(target, options) {
  if (!options.lfi) return [];
  const vulnerabilities = [];
  try {
    const response = await fetch(`${target}/?file=../../../../etc/passwd`);
    const data = await response.text();
    if (data.includes("root") || data.includes("www-data")) {
      let relevantData = data.split("\n").slice(0, 10).join("\n");
      vulnerabilities.push(`[+] LFI exploit successful: Exposed sensitive data - \n${relevantData}`);
    }
  } catch (error) {
    console.error("Error in LFI scan:", error);
  }
  return vulnerabilities;
}

// Remote Code Execution (RCE) scan
async function scanRCE(target, options) {
  if (!options.rce) return [];
  const vulnerabilities = [];
  try {
      const response = await fetch(`${target}/?cmd=whoami`);
      const data = await response.text();
      
      // Extract command output from <pre> tags if available
      const match = data.match(/<pre>(.*?)<\/pre>/s);
      const commandOutput = match ? match[1].trim() : data.trim(); // Use raw response if no <pre> tags

      if (commandOutput.includes("www-data") || commandOutput.includes("root")) {
          vulnerabilities.push(`[+] RCE exploit successful! Command executed: ${commandOutput}`);
      } else {
          vulnerabilities.push(`[!] RCE exploit unsuccessful. Command output: ${commandOutput}`);
      }

  } catch (error) {
      console.error("Error in RCE scan:", error);
      vulnerabilities.push("❌ Error occurred during RCE scan.");
  }
  return vulnerabilities;
}


// Detect outdated Nginx version
async function scanNginx(target, options) {
  if (!options.nginx) return [];
  const vulnerabilities = [];
  try {
    const response = await fetch(target);
    const serverHeader = response.headers.get("server");
    if (serverHeader && serverHeader.toLowerCase().includes("nginx")) {
        const versionMatch = serverHeader.match(/nginx\/(\d+\.\d+\.\d+)/);
        if (versionMatch) {
            const detectedVersion = versionMatch[1];
            vulnerabilities.push(`[+] Detected Nginx version: ${detectedVersion}`);
            const latestVersion = await getLatestNginxVersionOfficial();
            if (latestVersion && isVersionOutdated(detectedVersion, latestVersion)) {
              vulnerabilities.push(`[!] Nginx outdated! Latest: ${latestVersion}`);
            }
        }
    }
  } catch (error) {
    console.error("Nginx scan error:", error);
  }
  return vulnerabilities;
}

// Detect outdated PHP version
async function scanPHP(target, options) {
  if (!options.php) return [];
  const vulnerabilities = [];
  try {
    const response = await fetch(target);
    const phpHeader = response.headers.get("x-powered-by");
    if (phpHeader && phpHeader.toLowerCase().includes("php")) {
        const versionMatch = phpHeader.match(/php\/(\d+\.\d+\.\d+)/i);
        if (versionMatch) {
            const detectedVersion = versionMatch[1];
            vulnerabilities.push(`[+] Detected PHP version: ${detectedVersion}`);
            const latestVersion = await getLatestPHPVersionOfficial();
            if (latestVersion && isVersionOutdated(detectedVersion, latestVersion)) {
              vulnerabilities.push(`[!] PHP outdated! Latest: ${latestVersion}`);
            }
        }
    }
  } catch (error) {
    console.error("PHP scan error:", error);
  }
  return vulnerabilities;
}

// Detect missing Content Security Policy (CSP)
async function scanCSP(target) {
  const vulnerabilities = [];
  try {
    const response = await fetch(target);
    if (!response.headers.get("content-security-policy")) {
      vulnerabilities.push("[!] No Content Security Policy (CSP) detected, may be vulnerable to XSS.");
    }
  } catch (error) {
    console.error("Error in CSP scan:", error);
  }
  return vulnerabilities;
}

// Main scan handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scan") {
    (async () => {
    const { target, options } = request;
    let vulnerabilities = [];

    // Run all scans in parallel
    vulnerabilities = vulnerabilities.concat(await scanReflectedXSS(target, options));
    vulnerabilities = vulnerabilities.concat(await scanStoredXSS(target, options));
    vulnerabilities = vulnerabilities.concat(await scanLFI(target, options));
    vulnerabilities = vulnerabilities.concat(await scanRCE(target, options));
    vulnerabilities = vulnerabilities.concat(await scanNginx(target, options));
    vulnerabilities = vulnerabilities.concat(await scanPHP(target, options));
    vulnerabilities = vulnerabilities.concat(await scanCSP(target));

    sendResponse({ message: vulnerabilities.length ? vulnerabilities.join("\n") : "[-] No vulnerabilities detected." });
  })();
  return true; // Keep the channel open for async response
  }
});
