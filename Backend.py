import re
import time
import secrets
import string
from typing import List

import bcrypt
import mysql.connector
import requests
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

# ---------- CONFIG ----------

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

VT_API_KEY = "19f34c38c0da8762e48f3e044b553cad17e4bfcebb79a4e2c0ceeed089b0465a"
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/"


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))


def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="personal_dashboard",
    )


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev: allow all
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- MODELS ----------


class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class PasswordCheckRequest(BaseModel):
    platform: str
    username: str
    password: str


class PasswordCheckResponse(BaseModel):
    score: int
    rating: str
    suggestions: List[str]
    suggested_password: str


class SaveCredentialsRequest(BaseModel):
    user_id: int
    user_name: str
    passw: str
    platform: str
    strength_score: int


class UpdatePlatformPasswordRequest(BaseModel):
    user_id: int
    platform: str
    new_password: str
    strength_score: int


class DeleteCredentialsRequest(BaseModel):
    user_id: int
    platform: str
    user_name: str


class EmailBreachRequest(BaseModel):
    email: EmailStr


class EmailBreachResponse(BaseModel):
    breached: bool
    breach_count: int


class WebsiteCheckRequest(BaseModel):
    url: str


class WebsiteCheckResponse(BaseModel):
    dangerous: bool
    reasons: List[str]


class FileScanResponse(BaseModel):
    status: str
    malicious: bool
    detections: int
    total_engines: int
    threat_names: List[str]


# ---- NEW: profile models ----
class ProfileResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr


class UpdateProfileRequest(BaseModel):
    user_id: int
    name: str
    email: EmailStr


class UpdateUserPasswordRequest(BaseModel):
    user_id: int
    new_password: str


# ---------- AUTH ROUTES ----------


@app.post("/api/signup")
def signup(req: SignupRequest):
    if not is_valid_email(req.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT user_id FROM user_info WHERE user_mail = %s", (req.email,))
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Account with this email already exists")

    pw_bytes = req.password.encode("utf-8")
    hashed = bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")

    sql = "INSERT INTO user_info (user_name, user_mail, passw) VALUES (%s, %s, %s)"
    cur.execute(sql, (req.name, req.email, hashed))
    conn.commit()
    cur.close()
    conn.close()

    return {"message": "Account created successfully"}


@app.post("/api/login")
def login(req: LoginRequest):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    sql = "SELECT * FROM user_info WHERE user_mail = %s"
    cur.execute(sql, (req.email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    stored_hash = user["passw"].encode("utf-8")
    pw_bytes = req.password.encode("utf-8")

    if not bcrypt.checkpw(pw_bytes, stored_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return {
        "message": f"Welcome, {user['user_name']}",
        "user_id": user["user_id"],
    }


# ---------- PASSWORD STRENGTH (platform) ----------


def score_password(pw: str) -> int:
    score = 0
    length = len(pw)

    if length >= 8:
        score += 20
    if length >= 12:
        score += 20
    if re.search(r"[a-z]", pw):
        score += 15
    if re.search(r"[A-Z]", pw):
        score += 15
    if re.search(r"[0-9]", pw):
        score += 15
    if re.search(r"[^A-Za-z0-9]", pw):
        score += 15

    return min(score, 100)


def classify_score(score: int) -> str:
    if score < 30:
        return "Very Weak"
    elif score < 50:
        return "Weak"
    elif score < 70:
        return "OK"
    elif score < 85:
        return "Strong"
    else:
        return "Very Strong"


def generate_suggestions(pw: str, score: int) -> List[str]:
    suggestions: List[str] = []

    if len(pw) < 12:
        suggestions.append("Use at least 12 characters.")
    if not re.search(r"[A-Z]", pw):
        suggestions.append("Add at least one uppercase letter.")
    if not re.search(r"[a-z]", pw):
        suggestions.append("Add at least one lowercase letter.")
    if not re.search(r"[0-9]", pw):
        suggestions.append("Add at least one number.")
    if not re.search(r"[^A-Za-z0-9]", pw):
        suggestions.append("Add at least one symbol (e.g. !, #, ?, %).")
    if score < 70:
        suggestions.append("Avoid reusing passwords across different sites.")
        suggestions.append("Avoid using personal information (name, birthday, etc.).")

    if not suggestions:
        suggestions.append("Your password looks strong. Consider changing it every 3–6 months.")

    return suggestions


def generate_strong_password(username: str, platform: str) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(chars) for _ in range(16))


@app.post("/api/check_password", response_model=PasswordCheckResponse)
def check_password(req: PasswordCheckRequest):
    pw = req.password

    score = score_password(pw)
    rating = classify_score(score)
    suggestions = generate_suggestions(pw, score)
    suggested_password = generate_strong_password(req.username, req.platform)

    return PasswordCheckResponse(
        score=score,
        rating=rating,
        suggestions=suggestions,
        suggested_password=suggested_password,
    )


# ---------- PLATFORM CREDENTIALS ----------


@app.post("/api/save_credentials")
def save_credentials(req: SaveCredentialsRequest):
    conn = get_connection()
    cur = conn.cursor()

    pw_bytes = req.passw.encode("utf-8")
    hashed_pw = bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")

    sql = """
        INSERT INTO platform_credentials (user_id, user_name, passw, platform, strength_score)
        VALUES (%s, %s, %s, %s, %s)
    """
    cur.execute(
        sql,
        (req.user_id, req.user_name, hashed_pw, req.platform, req.strength_score),
    )
    conn.commit()

    cur.close()
    conn.close()

    return {"message": "Credentials saved successfully"}


@app.post("/api/update_platform_password")
def update_platform_password(req: UpdatePlatformPasswordRequest):
    conn = get_connection()
    cur = conn.cursor()

    pw_bytes = req.new_password.encode("utf-8")
    hashed_pw = bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")

    cur.execute(
        "SELECT user_name FROM platform_credentials WHERE user_id = %s AND platform = %s LIMIT 1",
        (req.user_id, req.platform),
    )
    row = cur.fetchone()

    if row:
        cur.execute(
            """
            UPDATE platform_credentials
               SET passw = %s,
                   strength_score = %s
             WHERE user_id = %s
               AND platform = %s
            """,
            (hashed_pw, req.strength_score, req.user_id, req.platform),
        )
    else:
        placeholder_user_name = req.platform
        cur.execute(
            """
            INSERT INTO platform_credentials (user_id, user_name, passw, platform, strength_score)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (req.user_id, placeholder_user_name, hashed_pw, req.platform, req.strength_score),
        )

    conn.commit()
    cur.close()
    conn.close()

    return {"message": "Platform password updated successfully"}


@app.post("/api/delete_credentials")
def delete_credentials(req: DeleteCredentialsRequest):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM platform_credentials
         WHERE user_id = %s
           AND platform = %s
           AND user_name = %s
        """,
        (req.user_id, req.platform, req.user_name),
    )
    conn.commit()

    cur.close()
    conn.close()

    return {"message": "Credentials deleted (if they existed)"}


# ---------- NEW: PROFILE ROUTES (username/email + login password) ----------


@app.get("/api/get_profile", response_model=ProfileResponse)
def get_profile(user_id: int):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT user_id, user_name, user_mail FROM user_info WHERE user_id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    return ProfileResponse(
        user_id=row["user_id"],
        name=row["user_name"],
        email=row["user_mail"],
    )


@app.post("/api/update_profile")
def update_profile(req: UpdateProfileRequest):
    if not is_valid_email(req.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    conn = get_connection()
    cur = conn.cursor()

    # ensure email is unique for other users
    cur.execute(
        "SELECT user_id FROM user_info WHERE user_mail = %s AND user_id <> %s",
        (req.email, req.user_id),
    )
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Another account already uses this email")

    cur.execute(
        "UPDATE user_info SET user_name = %s, user_mail = %s WHERE user_id = %s",
        (req.name, req.email, req.user_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    return {"message": "Profile updated successfully"}


@app.post("/api/update_user_password")
def update_user_password(req: UpdateUserPasswordRequest):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT user_id FROM user_info WHERE user_id = %s", (req.user_id,))
    if not cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    pw_bytes = req.new_password.encode("utf-8")
    hashed = bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")

    cur.execute(
        "UPDATE user_info SET passw = %s WHERE user_id = %s",
        (hashed, req.user_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    return {"message": "Login password updated successfully"}


# ---------- EMAIL BREACH ----------


def check_email_breach_raw(email: str):
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    headers = {
        "User-Agent": "personal-cybersecurity-dashboard-hackathon"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException as e:
        print("Error contacting XposedOrNot:", e)
        return None, 0

    if resp.status_code == 200:
        data = resp.json()
        breached = data.get("breached", False)
        breach_count = data.get("breach_count", 0)
        return bool(breached), int(breach_count)
    elif resp.status_code == 404:
        return False, 0
    else:
        print("XposedOrNot API error:", resp.status_code, resp.text)
        return None, 0


@app.post("/api/check_email_breach", response_model=EmailBreachResponse)
def check_email_breach(req: EmailBreachRequest):
    breached, count = check_email_breach_raw(req.email)

    if breached is None:
        raise HTTPException(status_code=502, detail="Error contacting breach service")

    return EmailBreachResponse(breached=breached, breach_count=count)


# ---------- WEBSITE SAFETY ----------


def basic_url_risk_rules(url: str):
    url_lower = url.lower()
    reasons = []

    if url_lower.startswith("http://"):
        reasons.append("Site does not use HTTPS.")
    if url_lower.count("-") > 3:
        reasons.append("Too many hyphens in domain (often used in phishing).")
    if any(tld in url_lower for tld in [".xyz", ".top", ".click", ".rest", ".info"]):
        reasons.append("Site uses a high-risk TLD (.xyz, .top, .click, .rest, .info).")
    if "login" in url_lower and not url_lower.startswith("https://"):
        reasons.append("Login-like URL but not using HTTPS.")

    return reasons


def check_phishtank(url: str) -> bool:
    api_url = "https://checkurl.phishtank.com/checkurl/"
    try:
        resp = requests.post(api_url, data={"url": url}, timeout=10)
        text = resp.text.lower()
        if "phish_detail_url" in text:
            return True
        return False
    except Exception as e:
        print("Error contacting PhishTank:", e)
        return False


@app.post("/api/check_website_safety", response_model=WebsiteCheckResponse)
def check_website_safety(req: WebsiteCheckRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    reasons: List[str] = []

    reasons.extend(basic_url_risk_rules(url))

    if check_phishtank(url):
        reasons.append("This site is reported as a phishing site (PhishTank).")

    if not reasons:
        return WebsiteCheckResponse(dangerous=False, reasons=["No known issues detected."])
    else:
        return WebsiteCheckResponse(dangerous=True, reasons=reasons)


# ---------- FILE MALWARE SCAN ----------


def upload_to_virustotal(file_bytes: bytes, filename: str):
    headers = {
        "x-apikey": VT_API_KEY
    }
    files = {
        "file": (filename, file_bytes)
    }

    resp = requests.post(VT_UPLOAD_URL, headers=headers, files=files)
    if resp.status_code not in (200, 202):
        print("Error uploading to VirusTotal:", resp.status_code, resp.text)
        return None

    data = resp.json()
    return data["data"]["id"]


def get_virustotal_result(analysis_id: str):
    headers = {
        "x-apikey": VT_API_KEY
    }
    while True:
        resp = requests.get(VT_ANALYSIS_URL + analysis_id, headers=headers)
        if resp.status_code != 200:
            print("Error fetching VT result:", resp.status_code, resp.text)
            return None

        data = resp.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            return data

        time.sleep(2)


@app.post("/api/scan_file", response_model=FileScanResponse)
async def scan_file(file: UploadFile = File(...)):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VirusTotal API key not configured on server")

    file_bytes = await file.read()

    analysis_id = upload_to_virustotal(file_bytes, file.filename)
    if analysis_id is None:
        raise HTTPException(status_code=500, detail="Error uploading file to VirusTotal")

    result = get_virustotal_result(analysis_id)
    if result is None:
        raise HTTPException(status_code=500, detail="Error retrieving analysis from VirusTotal")

    attrs = result["data"]["attributes"]
    stats = attrs.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    threat_names: List[str] = []
    results_detail = attrs.get("results", {})
    if isinstance(results_detail, dict):
        for engine, info in results_detail.items():
            if info.get("category") == "malicious":
                threat_names.append(info.get("result") or "Unknown threat")

    total_engines = malicious + suspicious + harmless + undetected
    if total_engines == 0:
        total_engines = len(results_detail) if isinstance(results_detail, dict) else 0

    return FileScanResponse(
        status="completed",
        malicious=(malicious > 0 or suspicious > 0),
        detections=malicious + suspicious,
        total_engines=total_engines,
        threat_names=threat_names,
    )
