document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("scanButton").addEventListener("click", function() {
        let targetUrl = document.getElementById("targetUrl").value.trim();

        if (!targetUrl) {
            document.getElementById("result").innerText = "⚠️ Please enter a target URL.";
            return;
        }

        let options = {
            xss: document.getElementById("xssCheckbox").checked,
            storedXss: document.getElementById("storedXssCheckbox").checked,
            lfi: document.getElementById("lfiCheckbox").checked,
            rce: document.getElementById("rceCheckbox").checked,
            // sql: document.getElementById("sqlCheckbox").checked,
            nginx: document.getElementById("nginxCheckbox").checked,
            php: document.getElementById("phpCheckbox").checked,
            phpunit: document.getElementById("phpunitCheckbox").checked
        };

        let downloadReport = document.getElementById("downloadReportCheckbox").checked;

        document.getElementById("result").innerText = "🔄 Scanning... Please wait.";

        chrome.runtime.sendMessage({ action: "scan", target: targetUrl, options: options }, function(response) {
            let scanResults = response?.message || "❌ Error: No response received.";
            document.getElementById("result").innerText = scanResults;

            // ✅ Only download if the user checked the box
            if (downloadReport) {
                let reportContent = `Scan Report for: ${targetUrl}\n\n${scanResults}`;
                let blob = new Blob([reportContent], { type: "text/plain" });
                let url = URL.createObjectURL(blob);
                let a = document.createElement("a");
                a.href = url;
                a.download = "scan_report.txt";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            }
        });
    });
});
