"""Agro Care AI - auth backend with email OTP (FastAPI + PostgreSQL + Gmail SMTP)."""
import hashlib, hmac, os, secrets, smtplib, ssl
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import bcrypt, jwt, psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

load_dotenv()
env = os.getenv
JWT_SECRET, OTP_SECRET = env("JWT_SECRET"), env("OTP_SECRET")
if not JWT_SECRET or not OTP_SECRET:
    raise RuntimeError("Set JWT_SECRET and OTP_SECRET in .env")

OTP_TTL_MIN, MAX_ATTEMPTS, MAX_CODES_PER_15_MIN, TOKEN_HOURS = 5, 5, 5, 8

app = FastAPI(title="Agro Care AI API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in env("CORS_ORIGINS", "").split(",") if o.strip()],
    allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"],
)
bearer = HTTPBearer()


def now():  # timezone-aware UTC, matches TIMESTAMPTZ columns
    return datetime.now(timezone.utc)


@contextmanager
def db():
    with psycopg.connect(
            host=env("DB_HOST", "127.0.0.1"), port=int(env("DB_PORT", "5432")),
            user=env("DB_USER"), password=env("DB_PASSWORD"), dbname=env("DB_NAME"),
            autocommit=True, row_factory=dict_row) as conn:
        yield conn


def check_pw(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def code_hash(user_id: int, code: str) -> str:
    return hmac.new(OTP_SECRET.encode(), f"{user_id}:{code}".encode(), hashlib.sha256).hexdigest()


def send_code_email(to: str, code: str):
    msg = EmailMessage()
    msg["Subject"] = f"Agro Care AI verification code: {code}"
    msg["From"] = f"{env('MAIL_FROM_NAME', 'Agro Care AI')} <{env('SMTP_USER')}>"
    msg["To"] = to
    msg.set_content(
        f"Your Agro Care AI verification code is {code}\n"
        f"It expires in {OTP_TTL_MIN} minutes. If you did not try to log in, ignore this email.\n\n"
        f"আপনার Agro Care AI ভেরিফিকেশন কোড: {code}\n"
        f"কোডটি {OTP_TTL_MIN} মিনিট পর্যন্ত বৈধ। আপনি লগইন না করে থাকলে এই ইমেইল উপেক্ষা করুন।")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context(), timeout=15) as s:
        s.login(env("SMTP_USER"), env("SMTP_APP_PASSWORD"))
        s.send_message(msg)


class RegisterIn(BaseModel):
    full_name: str = Field(min_length=1, max_length=150)
    email: EmailStr
    password: str = Field(min_length=8, max_length=64)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=64)


class VerifyIn(BaseModel):
    otp_id: int
    code: str = Field(min_length=6, max_length=6)


@app.post("/auth/register", status_code=201)
def register(b: RegisterIn):
    pw = bcrypt.hashpw(b.password.encode(), bcrypt.gensalt()).decode()
    try:
        with db() as c, c.cursor() as cur:
            cur.execute("INSERT INTO users (full_name, email, password_hash) VALUES (%s,%s,%s)",
                        (b.full_name.strip(), b.email.lower(), pw))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "An account with this email already exists.")
    return {"ok": True}


@app.post("/auth/request-otp")
def request_otp(b: LoginIn):
    with db() as c, c.cursor() as cur:
        cur.execute("SELECT id, email, password_hash, role, status FROM users WHERE email=%s", (b.email.lower(),))
        u = cur.fetchone()
        if not u or not check_pw(b.password, u["password_hash"]):
            raise HTTPException(401, "Invalid email or password.")
        if u["status"] != "ACTIVE":
            raise HTTPException(403, "Your account is disabled. Please contact an administrator.")
        if u["role"] != "USER":
            raise HTTPException(403, "Admin accounts must use the admin login.")
        cur.execute("SELECT COUNT(*) AS n FROM otp_codes WHERE user_id=%s AND created_at>%s",
                    (u["id"], now() - timedelta(minutes=15)))
        if cur.fetchone()["n"] >= MAX_CODES_PER_15_MIN:
            raise HTTPException(429, "Too many codes requested. Please try again later.")
        code = str(secrets.randbelow(900000) + 100000)
        cur.execute("INSERT INTO otp_codes (user_id, code_hash, expires_at) VALUES (%s,%s,%s) RETURNING id",
                    (u["id"], code_hash(u["id"], code), now() + timedelta(minutes=OTP_TTL_MIN)))
        otp_id = cur.fetchone()["id"]
    try:
        send_code_email(u["email"], code)
    except Exception:
        raise HTTPException(502, "Could not send the email. Please try again.")
    return {"otp_id": otp_id}


@app.post("/auth/verify-otp")
def verify_otp(b: VerifyIn):
    with db() as c, c.cursor() as cur:
        cur.execute("""SELECT o.id, o.user_id, o.code_hash, o.attempts, o.used_at, o.expires_at,
                              u.full_name, u.email, u.role, u.status, u.preferred_language
                       FROM otp_codes o JOIN users u ON u.id=o.user_id WHERE o.id=%s""", (b.otp_id,))
        r = cur.fetchone()
        if not r or r["used_at"] or r["expires_at"] < now() or r["attempts"] >= MAX_ATTEMPTS:
            raise HTTPException(400, "Code is invalid or expired. Please log in again.")
        cur.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE id=%s", (r["id"],))
        if not hmac.compare_digest(r["code_hash"], code_hash(r["user_id"], b.code)):
            raise HTTPException(400, "Incorrect code.")
        if r["status"] != "ACTIVE":
            raise HTTPException(403, "Your account is disabled.")
        cur.execute("UPDATE otp_codes SET used_at=%s WHERE id=%s", (now(), r["id"]))
    token = jwt.encode({"sub": str(r["user_id"]), "role": r["role"],
                        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)},
                       JWT_SECRET, algorithm="HS256")
    return {"token": token, "user": {"id": r["user_id"], "full_name": r["full_name"], "email": r["email"],
                                      "role": r["role"], "preferred_language": r["preferred_language"]}}


def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(cred.credentials, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token.")


@app.get("/me")
def me(claims=Depends(current_user)):
    with db() as c, c.cursor() as cur:
        cur.execute("SELECT id, full_name, email, role, preferred_language FROM users WHERE id=%s AND status='ACTIVE'",
                    (int(claims["sub"]),))
        u = cur.fetchone()
    if not u:
        raise HTTPException(401, "Account not found or disabled.")
    return u
