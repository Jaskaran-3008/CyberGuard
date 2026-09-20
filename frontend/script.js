// =====================================================
// CYBERGUARD SCRIPT.JS
// =====================================================


// =====================================================
// GLOBAL DATA
// =====================================================

let latestAnalysis = null;


// =====================================================
// ANALYZE SAMPLE LOGS
// =====================================================

async function analyzeSample() {

    try {

        const response = await fetch("/analyze");


        if (!response.ok) {
            throw new Error(
                "Failed to analyze sample logs."
            );
        }


        const data =
            await response.json();


        latestAnalysis = data;


        displayResults(data);

    } catch (error) {

        console.error(error);

        alert(
            "Unable to analyze sample logs."
        );

    }
}


// =====================================================
// ANALYZE UPLOADED FILE
// =====================================================

async function analyzeUploadedFile() {

    const fileInput =
        document.getElementById(
            "logFile"
        );


    if (!fileInput.files.length) {

        alert(
            "Please choose a .txt log file first."
        );

        return;
    }


    const formData =
        new FormData();


    formData.append(
        "file",
        fileInput.files[0]
    );


    try {

        const response =
            await fetch(
                "/upload-analyze",
                {
                    method: "POST",
                    body: formData
                }
            );


        if (!response.ok) {
            throw new Error(
                "Upload failed."
            );
        }


        const data =
            await response.json();


        latestAnalysis = data;


        displayResults(data);


    } catch (error) {

        console.error(error);

        alert(
            "Unable to analyze uploaded file."
        );

    }
}


// =====================================================
// DISPLAY ALL RESULTS
// =====================================================

function displayResults(data) {

    // -------------------------------------------------
    // SUMMARY
    // -------------------------------------------------

    document.getElementById(
        "totalLogs"
    ).textContent =
        data.total_logs ?? 0;


    const failedAttempts =
        Object.values(
            data.failed_login_ips || {}
        ).reduce(
            (sum, value) =>
                sum + Number(value),
            0
        );


    document.getElementById(
        "failedAttempts"
    ).textContent =
        failedAttempts;


    document.getElementById(
        "threatCount"
    ).textContent =
        (data.threats || []).length;


    // -------------------------------------------------
    // AI ANALYSIS
    // -------------------------------------------------

    displayAIAnalysis(
        data.ai_analysis
    );


    // -------------------------------------------------
    // THREATS
    // -------------------------------------------------

    displayThreats(
        data.threats || []
    );


    // -------------------------------------------------
    // THREAT INTELLIGENCE TABLE
    // -------------------------------------------------

    displayThreatTable(
        data.threats || []
    );


    // -------------------------------------------------
    // SECURITY ANALYTICS
    // -------------------------------------------------

    updateAnalytics(data);


    // -------------------------------------------------
    // SECURITY SCORE
    // -------------------------------------------------

    updateSecurityScore(data);


    // -------------------------------------------------
    // SECURITY RECOMMENDATIONS
    // -------------------------------------------------

    generateRecommendations(
        data.threats || [],
        data.ai_analysis || {}
    );

}


// =====================================================
// AI RISK ANALYSIS
// =====================================================

function displayAIAnalysis(ai) {

    const aiResult =
        document.getElementById(
            "aiResult"
        );


    if (!ai) {

        aiResult.innerHTML = `

            <div class="empty-message">

                No AI analysis available.

            </div>

        `;

        return;
    }


    const level =
        String(
            ai.threat_level || "LOW"
        ).toUpperCase();


    aiResult.className =
        "ai-result " +
        level.toLowerCase();


    aiResult.innerHTML = `

        <div class="ai-item">

            <span>
                Prediction
            </span>

            <strong>
                ${ai.prediction || "Unknown"}
            </strong>

        </div>


        <div class="ai-item">

            <span>
                Risk Score
            </span>

            <strong>
                ${ai.risk_score ?? 0}/100
            </strong>

        </div>


        <div class="ai-item">

            <span>
                Threat Level
            </span>

            <strong>
                ${level}
            </strong>

        </div>

    `;
}


// =====================================================
// DISPLAY THREATS
// =====================================================

function displayThreats(threats) {

    const container =
        document.getElementById(
            "threatResults"
        );


    if (!threats.length) {

        container.innerHTML = `

            <div class="safe-message">

                ✅ No suspicious activity detected.

            </div>

        `;

        return;
    }


    container.innerHTML =
        threats.map(
            threat => `

                <div class="threat-item">

                    <h3>

                        🚨
                        ${threat.threat ||
                        "Security Threat"}

                    </h3>


                    <p>

                        <strong>
                            IP Address:
                        </strong>

                        ${threat.ip_address ||
                        "Unknown"}

                    </p>


                    <p>

                        <strong>
                            Failed Attempts:
                        </strong>

                        ${threat.failed_attempts ||
                        0}

                    </p>


                    <p>

                        <strong>
                            Risk:
                        </strong>

                        <span class="risk-high">

                            🔴
                            ${threat.risk ||
                            "UNKNOWN"}

                        </span>

                    </p>

                </div>

            `
        ).join("");
}


// =====================================================
// THREAT INTELLIGENCE TABLE
// =====================================================

function displayThreatTable(threats) {

    const tableBody =
        document.getElementById(
            "threatTableBody"
        );


    if (!tableBody) {
        return;
    }


    if (!threats.length) {

        tableBody.innerHTML = `

            <tr>

                <td colspan="5">

                    No threats detected.

                </td>

            </tr>

        `;

        return;
    }


    tableBody.innerHTML =
        threats.map(
            threat => {

                const risk =
                    String(
                        threat.risk ||
                        "UNKNOWN"
                    ).toUpperCase();


                let status;


                if (risk === "HIGH") {

                    status =
                        "Action Required";

                }

                else if (
                    risk === "MEDIUM"
                ) {

                    status =
                        "Monitor";

                }

                else {

                    status =
                        "Normal";

                }


                return `

                    <tr>

                        <td>
                            ${threat.ip_address ||
                            "Unknown"}
                        </td>


                        <td>
                            ${threat.failed_attempts ||
                            0}
                        </td>


                        <td>
                            ${threat.threat ||
                            "Unknown"}
                        </td>


                        <td>

                            <span
                                class="table-risk ${risk.toLowerCase()}"
                            >

                                ${risk}

                            </span>

                        </td>


                        <td>
                            ${status}
                        </td>

                    </tr>

                `;

            }
        ).join("");
}


// =====================================================
// SECURITY ANALYTICS
// =====================================================

function updateAnalytics(data) {

    const failedIPs =
        data.failed_login_ips || {};


    const entries =
        Object.entries(
            failedIPs
        );


    createBarChart(entries);


    createDonutChart(
        data.threats || []
    );


    const ai =
        data.ai_analysis || {};


    document.getElementById(
        "analyticsRisk"
    ).textContent =
        `${ai.risk_score ?? 0}/100`;


    document.getElementById(
        "analyticsLevel"
    ).textContent =
        ai.threat_level || "LOW";


    document.getElementById(
        "analyticsThreats"
    ).textContent =
        (data.threats || []).length;

}


// =====================================================
// BAR CHART
// =====================================================

function createBarChart(entries) {

    const barChart =
        document.getElementById(
            "barChart"
        );


    if (!entries.length) {

        barChart.innerHTML = `

            <p class="empty-message">

                No failed attempts detected.

            </p>

        `;

        return;
    }


    const maxValue =
        Math.max(
            ...entries.map(
                item =>
                    Number(item[1])
            )
        );


    barChart.innerHTML =
        entries.map(
            ([ip, count]) => {

                const percentage =
                    maxValue > 0
                        ? (
                            Number(count) /
                            maxValue
                        ) * 100
                        : 0;


                return `

                    <div class="bar-row">

                        <div class="bar-label">
                            ${ip}
                        </div>


                        <div class="bar-wrapper">

                            <div
                                class="bar"
                                style="width: ${percentage}%"
                            >

                                ${count}

                            </div>

                        </div>

                    </div>

                `;

            }
        ).join("");
}


// =====================================================
// DONUT CHART
// =====================================================

function createDonutChart(threats) {

    const donut =
        document.getElementById(
            "donutChart"
        );


    const donutNumber =
        document.getElementById(
            "donutNumber"
        );


    const high =
        threats.filter(
            threat =>
                String(
                    threat.risk
                ).toUpperCase() === "HIGH"
        ).length;


    const medium =
        threats.filter(
            threat =>
                String(
                    threat.risk
                ).toUpperCase() === "MEDIUM"
        ).length;


    const low =
        threats.filter(
            threat =>
                String(
                    threat.risk
                ).toUpperCase() === "LOW"
        ).length;


    const total =
        high +
        medium +
        low;


    donutNumber.textContent =
        total;


    if (total === 0) {

        donut.style.background =
            "#3ba4e8";

        return;
    }


    const highPercent =
        (high / total) * 100;


    const mediumPercent =
        (medium / total) * 100;


    const mediumEnd =
        highPercent +
        mediumPercent;


    donut.style.background =
        `conic-gradient(
            #3ba4e8 0% ${highPercent}%,
            #ff5b83 ${highPercent}% ${mediumEnd}%,
            #ff9f43 ${mediumEnd}% 100%
        )`;
}


// =====================================================
// SECURITY SCORE
// =====================================================

function updateSecurityScore(data) {

    const scoreElement =
        document.getElementById(
            "securityScore"
        );


    const levelElement =
        document.getElementById(
            "securityScoreLevel"
        );


    const messageElement =
        document.getElementById(
            "securityScoreMessage"
        );


    const barElement =
        document.getElementById(
            "securityScoreBar"
        );


    if (!scoreElement) {
        return;
    }


    const ai =
        data.ai_analysis || {};


    const riskScore =
        Number(
            ai.risk_score ?? 0
        );


    const securityScore =
        Math.max(
            0,
            Math.min(
                100,
                100 - riskScore
            )
        );


    scoreElement.textContent =
        securityScore;


    if (barElement) {

        barElement.style.width =
            `${securityScore}%`;

    }


    if (securityScore >= 80) {

        levelElement.textContent =
            "Excellent Security";


        messageElement.textContent =
            "The analyzed activity shows a relatively low security risk.";

    }

    else if (securityScore >= 60) {

        levelElement.textContent =
            "Moderate Security";


        messageElement.textContent =
            "Some suspicious activity was detected. Continue monitoring your logs.";

    }

    else if (securityScore >= 40) {

        levelElement.textContent =
            "Elevated Risk";


        messageElement.textContent =
            "Several suspicious indicators were detected. Review the recommendations below.";

    }

    else {

        levelElement.textContent =
            "High Risk";


        messageElement.textContent =
            "Significant suspicious activity was detected. Review the detected threats and recommended actions.";

    }

}


// =====================================================
// SECURITY RECOMMENDATIONS
// =====================================================

function generateRecommendations(
    threats,
    ai
) {

    const container =
        document.getElementById(
            "recommendations"
        );


    if (!container) {
        return;
    }


    if (!threats.length) {

        container.innerHTML = `

            <div class="recommendation-safe">

                <div class="recommendation-icon">
                    ✅
                </div>


                <div>

                    <h3>
                        No Immediate Threats Detected
                    </h3>


                    <p>
                        Continue monitoring security logs
                        and maintain regular security checks.
                    </p>

                </div>

            </div>

        `;

        return;
    }


    let recommendations = [];


    const level =
        String(
            ai.threat_level || "LOW"
        ).toUpperCase();


    const score =
        Number(
            ai.risk_score || 0
        );


    if (
        level === "HIGH" ||
        score >= 70
    ) {

        recommendations.push({

            icon: "🚨",

            title:
                "Review High-Risk Login Activity",

            text:
                "Investigate repeated failed login attempts and review the affected accounts for suspicious activity."

        });


        recommendations.push({

            icon: "🔒",

            title:
                "Enable Multi-Factor Authentication",

            text:
                "Use MFA on important accounts to reduce the risk of unauthorized access even if passwords are compromised."

        });


        recommendations.push({

            icon: "🛑",

            title:
                "Consider IP Rate Limiting",

            text:
                "Limit repeated authentication attempts from the same IP address to reduce brute-force activity."

        });


        recommendations.push({

            icon: "📋",

            title:
                "Review Authentication Logs",

            text:
                "Check recent login records for unusual timestamps, usernames, locations, or repeated failures."

        });

    }

    else if (
        level === "MEDIUM" ||
        score >= 40
    ) {

        recommendations.push({

            icon: "👀",

            title:
                "Monitor Suspicious IP Addresses",

            text:
                "Continue monitoring IP addresses with repeated failed login attempts."

        });


        recommendations.push({

            icon: "🔐",

            title:
                "Strengthen Account Security",

            text:
                "Use strong passwords and enable multi-factor authentication for important accounts."

        });


        recommendations.push({

            icon: "📊",

            title:
                "Continue Log Monitoring",

            text:
                "Regularly analyze security logs to identify whether suspicious activity increases."

        });

    }

    else {

        recommendations.push({

            icon: "✅",

            title:
                "Continue Security Monitoring",

            text:
                "Current activity shows relatively low risk. Continue monitoring logs regularly."

        });


        recommendations.push({

            icon: "🔐",

            title:
                "Maintain Strong Authentication",

            text:
                "Continue using strong passwords and multi-factor authentication."

        });

    }


    threats.forEach(
        threat => {

            const risk =
                String(
                    threat.risk || ""
                ).toUpperCase();


            if (risk === "HIGH") {

                recommendations.push({

                    icon: "🌐",

                    title:
                        `Investigate IP ${threat.ip_address}`,

                    text:
                        `This IP generated ${threat.failed_attempts} failed attempts. Review the source and consider rate limiting or blocking it according to your security policy.`

                });

            }

            else if (
                risk === "MEDIUM"
            ) {

                recommendations.push({

                    icon: "⚠️",

                    title:
                        `Monitor IP ${threat.ip_address}`,

                    text:
                        `This IP generated ${threat.failed_attempts} failed attempts. Continue monitoring it for additional suspicious activity.`

                });

            }

        }
    );


    container.innerHTML =
        recommendations.map(
            recommendation => `

                <div class="recommendation-card">

                    <div class="recommendation-icon">

                        ${recommendation.icon}

                    </div>


                    <div class="recommendation-content">

                        <h3>

                            ${recommendation.title}

                        </h3>


                        <p>

                            ${recommendation.text}

                        </p>

                    </div>

                </div>

            `
        ).join("");
}


// =====================================================
// EXPORT SECURITY REPORT
// =====================================================

function exportSecurityReport() {

    const status =
        document.getElementById(
            "exportStatus"
        );


    if (!latestAnalysis) {

        if (status) {

            status.textContent =
                "Please analyze security logs before exporting a report.";

        }

        return;
    }


    const data =
        latestAnalysis;


    const ai =
        data.ai_analysis || {};


    const threats =
        data.threats || [];


    const failedIPs =
        data.failed_login_ips || {};


    const failedAttempts =
        Object.values(
            failedIPs
        ).reduce(
            (sum, value) =>
                sum + Number(value),
            0
        );


    const riskScore =
        Number(
            ai.risk_score ?? 0
        );


    const securityScore =
        Math.max(
            0,
            Math.min(
                100,
                100 - riskScore
            )
        );


    const reportDate =
        new Date().toLocaleString();


    let report = "";


    report +=
        "========================================\n";

    report +=
        "           CYBERGUARD SECURITY REPORT\n";

    report +=
        "========================================\n\n";


    report +=
        `Generated: ${reportDate}\n`;


    if (data.filename) {

        report +=
            `Analyzed File: ${data.filename}\n`;

    }

    else {

        report +=
            "Analyzed File: Sample Security Logs\n";

    }


    report += "\n";


    report +=
        "----------------------------------------\n";

    report +=
        "SECURITY OVERVIEW\n";

    report +=
        "----------------------------------------\n\n";


    report +=
        `Total Logs: ${data.total_logs ?? 0}\n`;

    report +=
        `Failed Attempts: ${failedAttempts}\n`;

    report +=
        `Threats Detected: ${threats.length}\n`;

    report +=
        `AI Risk Score: ${riskScore}/100\n`;

    report +=
        `AI Threat Level: ${ai.threat_level || "UNKNOWN"}\n`;

    report +=
        `AI Prediction: ${ai.prediction || "UNKNOWN"}\n`;

    report +=
        `Security Score: ${securityScore}/100\n\n`;


    report +=
        "----------------------------------------\n";

    report +=
        "FAILED ATTEMPTS BY IP\n";

    report +=
        "----------------------------------------\n\n";


    const ipEntries =
        Object.entries(
            failedIPs
        );


    if (!ipEntries.length) {

        report +=
            "No failed login attempts detected.\n\n";

    }

    else {

        ipEntries.forEach(
            ([ip, count]) => {

                report +=
                    `${ip} -> ${count} failed attempts\n`;

            }
        );

        report += "\n";

    }


    report +=
        "----------------------------------------\n";

    report +=
        "THREAT INTELLIGENCE\n";

    report +=
        "----------------------------------------\n\n";


    if (!threats.length) {

        report +=
            "No threats detected.\n\n";

    }

    else {

        threats.forEach(
            (threat, index) => {

                report +=
                    `Threat ${index + 1}\n`;

                report +=
                    `IP Address: ${threat.ip_address || "Unknown"}\n`;

                report +=
                    `Failed Attempts: ${threat.failed_attempts || 0}\n`;

                report +=
                    `Threat: ${threat.threat || "Unknown"}\n`;

                report +=
                    `Risk: ${threat.risk || "Unknown"}\n`;

                report += "\n";

            }
        );

    }


    report +=
        "----------------------------------------\n";

    report +=
        "SECURITY RECOMMENDATIONS\n";

    report +=
        "----------------------------------------\n\n";


    if (!threats.length) {

        report +=
            "Continue regular security monitoring.\n";

    }

    else {

        report +=
            "1. Review high-risk login activity.\n";

        report +=
            "2. Enable multi-factor authentication.\n";

        report +=
            "3. Consider IP rate limiting.\n";

        report +=
            "4. Review authentication logs.\n";

        report +=
            "5. Monitor repeated failed login attempts.\n";

    }


    report += "\n";


    report +=
        "========================================\n";

    report +=
        "Generated by CyberGuard\n";

    report +=
        "AI-Powered Cybersecurity Threat Detection\n";

    report +=
        "========================================\n";


    const blob =
        new Blob(
            [report],
            {
                type:
                    "text/plain;charset=utf-8"
            }
        );


    const url =
        URL.createObjectURL(
            blob
        );


    const link =
        document.createElement(
            "a"
        );


    link.href =
        url;


    link.download =
        "CyberGuard_Security_Report.txt";


    document.body.appendChild(
        link
    );


    link.click();


    document.body.removeChild(
        link
    );


    URL.revokeObjectURL(
        url
    );


    if (status) {

        status.textContent =
            "✅ Security report downloaded successfully.";

    }

}


// =====================================================
// SYSTEM HEALTH CHECK
// =====================================================

async function checkHealth() {

    try {

        const response =
            await fetch(
                "/health"
            );


        if (!response.ok) {

            throw new Error(
                "Health check failed."
            );

        }


        const data =
            await response.json();


        const status =
            document.getElementById(
                "systemStatus"
            );


        if (status) {

            if (data.status) {

                status.textContent =
                    "Active";

            }

            else {

                status.textContent =
                    "Offline";

            }

        }

    } catch (error) {

        console.error(error);


        const status =
            document.getElementById(
                "systemStatus"
            );


        if (status) {

            status.textContent =
                "Offline";

        }

    }
}


// =====================================================
// AUTO LOAD SAMPLE DATA
// =====================================================

async function loadInitialData() {

    try {

        const response =
            await fetch(
                "/analyze"
            );


        if (!response.ok) {
            return;
        }


        const data =
            await response.json();


        latestAnalysis =
            data;


        displayResults(
            data
        );


    } catch (error) {

        console.log(
            "Waiting for analysis..."
        );

    }
}


// =====================================================
// START APPLICATION
// =====================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        checkHealth();

        loadInitialData();

    }
);