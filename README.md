# 2214-WebSec-Grp3

**Description**
ExploitScan is a Chrome Extension that detects outdated components (Nginx, PHP, etc.), scan for the vulnerabilities associated with the outdated components and automatically exploits them.

**Features**

- *Scan for Reflected XSS* - Identifies reflected cross-site scripting vulnerabilities. 
- *Scan for Stored XSS* - Attempts to persist an XSS payload in forms.
- *Scan for LFI (Local File Inclusion)* - Identifies file inclusion vulnerabilities and exposed sensitive data like users.
- *Scan for RCE (Remote Code Execution)* - Checks for command execution vulnerabilities, detects who owned the web server (allowing priviledge escalation).
- *Check for Outdated Nginx* - Checks the current Nginx version for the website and compares with the latest version.
- *Check for Outdated PHP* - Checks the current PHP version for the website and compares with the latest version.
- *Scan for PHPUnit CVE-2017-9841*.
- *Report Generation* - Saves scan and exploit result in a structured report in a .txt format.

**Installation Guide**

*Step 1*: Clone Respository

*Step 2*: Open Google Chrome and head to extensions

*Step 3*: Enable Developer Mode

*Step 4*: Click "Load Unpacked" and select the "ExploitScan" folder

**How to use**

*Step 1*: Click the ExploitScan icon in the extension bar.

*Step 2*: Enter the target URL of the website you want to test.

*Step 3*: Choose one or more options such as outdated components or vulnerabilities to test.

*Step 4*: Click "Scan for Vulnerabilities".

*Step 5*: Get the results to appear in extension popup.

*Step 6*: (Optional) Donwload the report to save results as a structured text file.

**Future Enhancements**
- Allowing tool to be more dynamic: Scan for more components and vulnerabilities
- Allowing user to scan the website they are in, instead of entering the URL
- Better format for report
- Include wider variety of scanning and testing

**Contributors**
@marvinoon
@DesuNan
@jamestanzr
@PrinceRJ1271
@NewOyioyiball
