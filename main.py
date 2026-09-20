from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import re

from models.risk_model import predict_risk


app = FastAPI(title="CyberGuard")


# --------------------------------------------------
# PATHS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR = BASE_DIR / "data"


# --------------------------------------------------
# STATIC FILES
# --------------------------------------------------

app.mount(
    "/static",
    StaticFiles(directory=str(FRONTEND_DIR)),
    name="static"
)


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.get("/")
def home():
    return FileResponse(FRONTEND_DIR / "index.html")


# --------------------------------------------------
# LOG PARSER
# --------------------------------------------------

def analyze_logs(text: str):

    lines = text.splitlines()

    logs = []
    failed_attempts = {}

    for line in lines:

        line = line.strip()

        if not line:
            continue

        logs.append(line)

        # Find IP address
        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            line
        )

        if not ip_match:
            continue

        ip = ip_match.group()

        # Detect failed login / failed attempt
        failed = re.search(
            r"(failed|failure|denied|invalid|unsuccessful)",
            line,
            re.IGNORECASE
        )

        if failed:

            if ip not in failed_attempts:
                failed_attempts[ip] = 0

            failed_attempts[ip] += 1


    # --------------------------------------------------
    # THREAT DETECTION
    # --------------------------------------------------

    threats = []

    for ip, count in failed_attempts.items():

        if count >= 4:

            threats.append({
                "ip_address": ip,
                "failed_attempts": count,
                "threat": "Possible Brute Force Attack",
                "risk": "HIGH"
            })

        elif count >= 2:

            threats.append({
                "ip_address": ip,
                "failed_attempts": count,
                "threat": "Suspicious Login Activity",
                "risk": "MEDIUM"
            })


    total_failed_attempts = sum(failed_attempts.values())

    unique_ips = len(failed_attempts)

    failure_ratio = (
        total_failed_attempts / len(logs)
        if len(logs) > 0
        else 0
    )


    # --------------------------------------------------
    # AI RISK ANALYSIS
    # --------------------------------------------------

    try:

        ai_result = predict_risk(
            failed_attempts=total_failed_attempts,
            unique_ips=unique_ips,
            failure_ratio=failure_ratio
        )

    except Exception:

        # Fallback if ML model fails
        if total_failed_attempts >= 8:
            risk_score = 85
            threat_level = "HIGH"
            prediction = "Suspicious"

        elif total_failed_attempts >= 4:
            risk_score = 64
            threat_level = "HIGH"
            prediction = "Suspicious"

        elif total_failed_attempts >= 2:
            risk_score = 40
            threat_level = "MEDIUM"
            prediction = "Suspicious"

        else:
            risk_score = 15
            threat_level = "LOW"
            prediction = "Normal"

        ai_result = {
            "prediction": prediction,
            "risk_score": risk_score,
            "threat_level": threat_level
        }


    return {
        "total_logs": len(logs),
        "failed_login_ips": failed_attempts,
        "threats": threats,
        "ai_analysis": ai_result
    }


# --------------------------------------------------
# ANALYZE SAMPLE LOGS
# --------------------------------------------------

@app.get("/analyze")
def analyze_sample_logs():

    sample_file = DATA_DIR / "security_logs.txt"

    if not sample_file.exists():

        return {
            "total_logs": 0,
            "failed_login_ips": {},
            "threats": [],
            "ai_analysis": {
                "prediction": "Normal",
                "risk_score": 0,
                "threat_level": "LOW"
            }
        }

    text = sample_file.read_text(
        encoding="utf-8",
        errors="ignore"
    )

    return analyze_logs(text)


# --------------------------------------------------
# UPLOAD AND ANALYZE FILE
# --------------------------------------------------

@app.post("/upload-analyze")
async def upload_analyze(file: UploadFile = File(...)):

    content = await file.read()

    text = content.decode(
        "utf-8",
        errors="ignore"
    )

    result = analyze_logs(text)

    result["filename"] = file.filename

    return result


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/health")
def health():

    return {
        "status": "CyberGuard is running",
        "ml_model": "Random Forest",
        "log_analysis": "Active"
    }