import re
import os
import json
import base64
import sqlite3
import secrets
import html
import time
from datetime import datetime, timedelta, date
from typing import List, Optional, Dict
from fastapi import FastAPI, HTTPException, Query, Request, Response, Depends, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

DB_FILE = "app.db"

app = FastAPI(title="Natali Nails Prive - Secure Beauty CRM")

# --- Security: Rate Limiting & Anti-Brute-Force Cache ---
RATE_LIMIT_CACHE: Dict[str, List[float]] = {}
FAILED_PIN_ATTEMPTS: Dict[str, List[float]] = {}
ACTIVE_SESSIONS: Dict[str, float] = {} # token -> expires_timestamp

def check_rate_limit(ip: str, max_requests: int = 15, window_seconds: int = 60) -> bool:
    now = time.time()
    timestamps = RATE_LIMIT_CACHE.get(ip, [])
    # Filter out timestamps outside window
    timestamps = [t for t in timestamps if now - t < window_seconds]
    if len(timestamps) >= max_requests:
        return False
    timestamps.append(now)
    RATE_LIMIT_CACHE[ip] = timestamps
    return True

def record_failed_pin(ip: str) -> bool:
    now = time.time()
    attempts = FAILED_PIN_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < 600] # 10 min window
    attempts.append(now)
    FAILED_PIN_ATTEMPTS[ip] = attempts
    return len(attempts) >= 5 # True if locked out

def is_pin_locked(ip: str) -> bool:
    now = time.time()
    attempts = FAILED_PIN_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < 600]
    return len(attempts) >= 5

def sanitize_text(text: Optional[str]) -> str:
    if not text:
        return ""
    # Strip dangerous HTML / script tags
    cleaned = html.escape(text.strip())
    return cleaned[:500] # Prevent buffer attacks

# --- Security Headers Middleware ---
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    # Prevent clickjacking and MIME sniffing
    response: Response = await call_next(request)
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


# --- Multi-Language Service Translation Engine ---
NAIL_TERMS_MAP = [
    (r"milky nude|clean girl", {
        "uk": "Clean Girl: Milky Nude (Комплекс)",
        "en": "Clean Girl: Milky Nude (Full Care)",
        "es": "Clean Girl: Milky Nude (Completo)",
        "de": "Clean Girl: Milky Nude (Komplex)",
        "va": "Clean Girl: Milky Nude (Complet)",
        "ru": "Clean Girl: Milky Nude (Комплекс)"
    }),
    (r"японський|japanese|японский", {
        "uk": "Японський еко-манікюр (P.Shine / Masura)",
        "en": "Japanese Eco-Manicure (P.Shine / Masura)",
        "es": "Manicura ecológica japonesa (P.Shine / Masura)",
        "de": "Japanische Öko-Maniküre (P.Shine / Masura)",
        "va": "Manicura ecològica japonesa",
        "ru": "Японский эко-маникюр (P.Shine / Masura)"
    }),
    (r"micro-french|френч|french", {
        "uk": "Трендовий Micro-French / Оксамитовий френч",
        "en": "Trendy Micro-French / Velvet French",
        "es": "Micro-French de tendencia / Francesa terciopelo",
        "de": "Trendiger Micro-French / Samt French",
        "va": "Micro-French de tendència / Francesa vellut",
        "ru": "Трендовый Micro-French / Бархатный френч"
    }),
    (r"cat eye|котяче око|кошачий глаз", {
        "uk": "Velvet Cat Eye (Оксамитове котяче око)",
        "en": "Velvet Cat Eye Gel Polish",
        "es": "Esmaltado Ojo de Gato Terciopelo (Cat Eye)",
        "de": "Velvet Cat Eye Maniküre",
        "va": "Ull de Gat Vellut (Cat Eye)",
        "ru": "Бархатный кошачий глаз (Cat Eye)"
    }),
    (r"гігієнічний|комбінований|апаратний|класичний манікюр", {
        "uk": "Гігієнічний апаратний манікюр + догляд",
        "en": "Hardware / Russian Manicure + Care",
        "es": "Manicura combinada / rusa con cuidado nutritivo",
        "de": "Kombinierte Apparat-Maniküre + Pflege",
        "va": "Manicura combinada / russa amb cura nutritiva",
        "ru": "Аппаратный / комбинированный маникюр + уход"
    }),
    (r"нарощування|моделювання|extensions", {
        "uk": "Нарощування та моделювання нігтів (гель / полігель)",
        "en": "Nail Extensions & Sculpting (Gel / Polygel)",
        "es": "Extensiones y modelado de uñas (Gel / Poligel)",
        "de": "Nagelverlängerung & Modellage (Gel / Polygel)",
        "va": "Extensions i modelatge d'ungles (Gel / Poligel)",
        "ru": "Наращивание и моделирование ногтей (гель / полигель)"
    }),
    (r"корекція нарощених|корекція|refill", {
        "uk": "Корекція нарощених нігтів",
        "en": "Nail Extension Refill / Correction",
        "es": "Relleno / Corrección de extensiones de uñas",
        "de": "Auffüllen / Nagelkorrektur",
        "va": "Farciment / Correcció d'extensions d'ungles",
        "ru": "Коррекция нарощенных ногтей"
    }),
    (r"зняття|removal|retirada", {
        "uk": "Зняття старого покриття",
        "en": "Old Polish / Gel Removal",
        "es": "Retirada de esmalte o gel antiguo",
        "de": "Altmaterial / Gellack entfernen",
        "va": "Retirada d'esmalt o gel antic",
        "ru": "Снятие старого покрытия"
    }),
    (r"педикюр з покриттям", {
        "uk": "Педикюр з покриттям гель-лак",
        "en": "Pedicure with Gel Polish",
        "es": "Pedicura con esmalte semipermanente",
        "de": "Pediküre mit Gellack",
        "va": "Pedicura amb esmalt semipermanent",
        "ru": "Педикюр с покрытием гель-лак"
    }),
    (r"педикюр", {
        "uk": "Педикюр гігієнічний / класичний",
        "en": "Classic Spa Pedicure",
        "es": "Pedicura higiénica completa",
        "de": "Klassische Pediküre",
        "va": "Pedicura completa",
        "ru": "Педикюр гигиенический / классический"
    }),
    (r"spa|парафін|paraffin", {
        "uk": "SPA-догляд для рук (холодний парафін)",
        "en": "SPA Hand Treatment (Cold Paraffin Therapy)",
        "es": "Tratamiento SPA para manos (Parafina fría)",
        "de": "SPA Handpflege (Kaltes Paraffin)",
        "va": "Tractament SPA per a mans (Parafina freda)",
        "ru": "SPA-уход для рук (холодный парафин)"
    }),
    (r"ремонт|repair", {
        "uk": "Ремонт 1 нігтя / нарощування кутика",
        "en": "1 Nail Repair / Corner Restoration",
        "es": "Reparación de 1 uña / Reconstrucción de esquina",
        "de": "Reparatur von 1 Nagel",
        "va": "Reparació d'1 ungla",
        "ru": "Ремонт 1 ногтя / донаращивание уголка"
    }),
    (r"манікюр з покриттям|гель[\s-]лак", {
        "uk": "Манікюр з покриттям гель-лак",
        "en": "Manicure with Gel Polish",
        "es": "Manicura con esmalte semipermanente",
        "de": "Maniküre mit Gellack",
        "va": "Manicura amb esmalt semipermanent",
        "ru": "Маникюр с покрытием гель-лак"
    }),
]

def auto_translate_service(name: str, description: str = "") -> dict:
    name_clean = (name or "").strip()
    desc_clean = (description or "").strip()
    name_l = name_clean.lower()

    res_names = {"uk": name_clean, "en": name_clean, "es": name_clean, "va": name_clean, "de": name_clean, "ru": name_clean}
    for pat, tr in NAIL_TERMS_MAP:
        if re.search(pat, name_l, re.IGNORECASE):
            for lang in ["uk", "en", "es", "va", "de", "ru"]:
                if lang in tr:
                    res_names[lang] = tr[lang]
            break

    res_descs = {"uk": desc_clean, "en": desc_clean, "es": desc_clean, "va": desc_clean, "de": desc_clean, "ru": desc_clean}
    return {
        "name": res_names,
        "description": res_descs
    }

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Settings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        master_name TEXT,
        studio_name TEXT,
        phone TEXT,
        instagram TEXT,
        telegram TEXT,
        address TEXT,
        work_start TEXT,
        work_end TEXT,
        slot_step INTEGER,
        currency TEXT DEFAULT '€',
        about TEXT,
        bizum_phone TEXT DEFAULT '+34 612 345 678',
        paypal_link TEXT DEFAULT 'paypal.me/nailstudio',
        accept_bizum INTEGER DEFAULT 1,
        accept_card INTEGER DEFAULT 1,
        accept_paypal INTEGER DEFAULT 1,
        accept_cash INTEGER DEFAULT 1,
        master_pin TEXT DEFAULT '1234'
    )
    """)

    # Services table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT DEFAULT 'Манікюр',
        price REAL NOT NULL,
        duration_minutes INTEGER NOT NULL,
        description TEXT DEFAULT '',
        is_active INTEGER DEFAULT 1
    )
    """)

    # Clients table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        instagram TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        points INTEGER DEFAULT 50,
        vip_tier TEXT DEFAULT 'Gold VIP',
        unlocked_emojis TEXT DEFAULT '💅,✨,💖',
        created_at TEXT
    )
    """)

    # Appointments table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER,
        client_name TEXT NOT NULL,
        client_phone TEXT NOT NULL,
        service_names TEXT NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        total_price REAL NOT NULL,
        status TEXT DEFAULT 'confirmed',
        payment_method TEXT DEFAULT 'cash',
        notes TEXT DEFAULT '',
        source TEXT DEFAULT 'master',
        created_at TEXT
    )
    """)

    # Finance transactions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        category TEXT NOT NULL,
        amount REAL NOT NULL,
        date TEXT NOT NULL,
        payment_method TEXT DEFAULT 'cash',
        appointment_id INTEGER,
        description TEXT DEFAULT '',
        created_at TEXT
    )
    """)

    # Reviews table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_name TEXT NOT NULL,
        client_phone TEXT NOT NULL,
        rating INTEGER DEFAULT 5,
        comment TEXT NOT NULL,
        emojis TEXT DEFAULT '',
        date TEXT NOT NULL
    )
    """)

    # Ensure master_pin column exists
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN master_pin TEXT DEFAULT '1234'")
    except Exception:
        pass

    # Ensure is_vip column exists
    try:
        cursor.execute("ALTER TABLE clients ADD COLUMN is_vip INTEGER DEFAULT 0")
    except Exception:
        pass

    # Ensure master_avatar column exists
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN master_avatar TEXT DEFAULT ''")
    except Exception:
        pass

    # Ensure client avatar_url column exists
    try:
        cursor.execute("ALTER TABLE clients ADD COLUMN avatar_url TEXT DEFAULT ''")
    except Exception:
        pass

    # Ensure service translations column exists
    try:
        cursor.execute("ALTER TABLE services ADD COLUMN translations TEXT DEFAULT '{}'")
    except Exception:
        pass

    # Populate translations for existing services if empty
    try:
        cursor.execute("SELECT id, name, description, translations FROM services")
        for s_row in cursor.fetchall():
            sid = s_row["id"]
            sname = s_row["name"]
            sdesc = s_row["description"] or ""
            strans = s_row["translations"] or ""
            if not strans or strans == "{}":
                gen_tr = json.dumps(auto_translate_service(sname, sdesc), ensure_ascii=False)
                cursor.execute("UPDATE services SET translations = ? WHERE id = ?", (gen_tr, sid))
    except Exception:
        pass

    # VIP Rewards table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vip_rewards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        icon TEXT DEFAULT '💎',
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        cost INTEGER NOT NULL,
        reward_type TEXT DEFAULT 'discount',
        is_active INTEGER DEFAULT 1
    )
    """)

    # Seed initial rewards if empty
    try:
        cursor.execute("SELECT COUNT(*) FROM vip_rewards")
        if cursor.fetchone()[0] == 0:
            default_rewards = [
                ('👑', 'Золота VIP-Корона', 'Ексклюзивний смайлик корони для ваших відгуків', 30, 'emoji'),
                ('💎', 'Діамантове сяйво', 'Смайлик діаманту поруч з вашим ім’ям', 25, 'emoji'),
                ('🔥', 'Вельветовий вогник', 'Смайлик тренду Velvet Nails', 20, 'emoji'),
                ('☕', 'Кава & Prosecco', 'Улюблений напій у студії безкоштовно', 15, 'gift'),
                ('🏷️', 'Знижка 1.50€ на візит', 'Приємна знижка на наступну процедуру', 100, 'discount'),
                ('🏷️', 'Знижка 2.50€ на візит', 'Супер-знижка на будь-який комплекс', 150, 'discount'),
                ('🌸', 'SPA-догляд для рук', 'Холодний парафін + скрабування в подарунок', 80, 'service')
            ]
            cursor.executemany("INSERT INTO vip_rewards (icon, title, description, cost, reward_type) VALUES (?, ?, ?, ?, ?)", default_rewards)
    except Exception:
        pass

    conn.commit()
    conn.close()

init_db()

# --- Pydantic Models with Validation ---
class MasterLoginRequest(BaseModel):
    pin: str = Field(..., min_length=4, max_length=64)

class ChangePinRequest(BaseModel):
    old_pin: str
    new_pin: str = Field(..., min_length=4, max_length=64)

class ServiceCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    category: Optional[str] = "Манікюр"
    price: float = Field(..., gt=0)
    duration_minutes: int = Field(..., gt=0, le=480)
    description: Optional[str] = ""
    is_active: Optional[int] = 1
    translations: Optional[str] = "{}"

class ClientCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    phone: str = Field(..., min_length=6, max_length=25)
    instagram: Optional[str] = ""
    notes: Optional[str] = ""

class AppointmentCreate(BaseModel):
    client_name: str
    client_phone: str
    service_names: str
    date: str
    time: str
    duration_minutes: int
    total_price: float
    payment_method: Optional[str] = "cash"
    notes: Optional[str] = ""
    source: Optional[str] = "master"

class TransactionCreate(BaseModel):
    type: str
    category: str
    amount: float
    date: str
    payment_method: Optional[str] = "cash"
    description: Optional[str] = ""

class SettingsUpdate(BaseModel):
    master_name: str
    studio_name: str
    phone: str
    instagram: Optional[str] = ""
    telegram: Optional[str] = ""
    address: str
    work_start: str
    work_end: str
    slot_step: int
    currency: str
    about: Optional[str] = ""
    bizum_phone: Optional[str] = ""
    paypal_link: Optional[str] = ""
    card_ua: Optional[str] = ""
    card_es: Optional[str] = ""
    accept_bizum: Optional[int] = 1
    accept_card: Optional[int] = 1
    accept_paypal: Optional[int] = 1
    accept_cash: Optional[int] = 1
    master_avatar: Optional[str] = ""

class MasterAvatarUpdate(BaseModel):
    master_avatar: str

class ClientAvatarUpdate(BaseModel):
    phone: str
    avatar_url: str

class PublicBookingRequest(BaseModel):
    client_name: str = Field(..., min_length=2, max_length=80)
    client_phone: str = Field(..., min_length=6, max_length=25)
    service_names: str
    total_duration: int
    total_price: float
    date: str
    time: str
    notes: Optional[str] = ""

class ClientLoginRequest(BaseModel):
    provider: str
    phone: str
    name: Optional[str] = ""
    instagram: Optional[str] = ""
    avatar_url: Optional[str] = ""

class ReviewCreate(BaseModel):
    client_name: str
    client_phone: str
    rating: int = Field(..., ge=1, le=5)
    comment: str = Field(..., min_length=3, max_length=500)
    emojis: Optional[str] = ""

class RedeemRequest(BaseModel):
    phone: str
    item_id: str
    points_cost: int

# --- Authentication Helpers ---
def add_minutes(time_str: str, minutes: int) -> str:
    t = datetime.strptime(time_str, "%H:%M")
    new_t = t + timedelta(minutes=minutes)
    return new_t.strftime("%H:%M")

def time_to_minutes(t_str: str) -> int:
    h, m = map(int, t_str.split(":"))
    return h * 60 + m

# --- Master Security & Authentication Endpoints ---

@app.post("/api/auth/master-login")
def master_login(data: MasterLoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"

    # Anti-Brute-Force check
    if is_pin_locked(client_ip):
        raise HTTPException(status_code=429, detail="Забагато невдалих спроб входу. Задля безпеки доступ заблоковано на 10 хвилин.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT master_pin FROM settings WHERE id = 1")
    row = cursor.fetchone()
    stored_pin = (row["master_pin"] if row and row["master_pin"] else "1234").strip()
    conn.close()

    if data.pin.strip() != stored_pin:
        locked = record_failed_pin(client_ip)
        if locked:
            raise HTTPException(status_code=429, detail="Невірний PIN-код! 5 невдалих спроб. Кабінет тимчасово заблоковано на 10 хвилин.")
        raise HTTPException(status_code=401, detail="Невірний PIN-код майстра!")

    # Login successful, generate secure session token
    token = secrets.token_hex(24)
    ACTIVE_SESSIONS[token] = time.time() + 86400 # valid for 24 hours
    return {"status": "ok", "token": token}

@app.post("/api/auth/change-pin")
def change_pin(data: ChangePinRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT master_pin FROM settings WHERE id = 1")
    row = cursor.fetchone()
    stored_pin = (row["master_pin"] if row and row["master_pin"] else "1234").strip()

    if data.old_pin.strip() != stored_pin:
        conn.close()
        raise HTTPException(status_code=400, detail="Старий PIN-код вказано невірно!")

    cursor.execute("UPDATE settings SET master_pin = ? WHERE id = 1", (data.new_pin.strip(),))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "PIN-код успішно змінено!"}

# --- Standard API Endpoints ---

@app.get("/api/settings")
def get_settings():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT master_name, studio_name, phone, instagram, telegram, address, work_start, work_end, slot_step, currency, about, bizum_phone, paypal_link, card_ua, card_es, accept_bizum, accept_card, accept_paypal, accept_cash, master_avatar FROM settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}

@app.post("/api/settings")
def update_settings(data: SettingsUpdate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE settings SET
        master_name = ?, studio_name = ?, phone = ?, instagram = ?,
        telegram = ?, address = ?, work_start = ?, work_end = ?,
        slot_step = ?, currency = ?, about = ?,
        bizum_phone = ?, paypal_link = ?, card_ua = ?, card_es = ?,
        accept_bizum = ?, accept_card = ?, accept_paypal = ?, accept_cash = ?,
        master_avatar = COALESCE(NULLIF(?, ''), master_avatar)
    WHERE id = 1
    """, (sanitize_text(data.master_name), sanitize_text(data.studio_name), sanitize_text(data.phone), sanitize_text(data.instagram),
          sanitize_text(data.telegram), sanitize_text(data.address), data.work_start, data.work_end,
          data.slot_step, data.currency, sanitize_text(data.about),
          sanitize_text(data.bizum_phone), sanitize_text(data.paypal_link),
          sanitize_text(data.card_ua), sanitize_text(data.card_es),
          data.accept_bizum, data.accept_card, data.accept_paypal, data.accept_cash,
          data.master_avatar or ''))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.post("/api/settings/avatar")
def update_master_avatar(data: MasterAvatarUpdate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET master_avatar = ? WHERE id = 1", (data.master_avatar,))
    conn.commit()
    conn.close()
    return {"status": "ok", "master_avatar": data.master_avatar}

@app.post("/api/settings/toggle-currency")
def toggle_currency():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT currency FROM settings WHERE id = 1")
    cur = cursor.fetchone()[0] or "€"
    new_cur = "грн" if cur == "€" else "€"

    cursor.execute("UPDATE settings SET currency = ? WHERE id = 1", (new_cur,))
    if new_cur == "грн":
        cursor.execute("UPDATE services SET price = price * 40 WHERE price < 100")
        cursor.execute("UPDATE appointments SET total_price = total_price * 40 WHERE total_price < 100")
    else:
        cursor.execute("UPDATE services SET price = ROUND(price / 40) WHERE price >= 100")
        cursor.execute("UPDATE appointments SET total_price = ROUND(total_price / 40) WHERE total_price >= 100")

    conn.commit()
    conn.close()
    return {"currency": new_cur}

@app.get("/api/services")
def get_services(active_only: bool = False):
    conn = get_db()
    cursor = conn.cursor()
    if active_only:
        cursor.execute("SELECT * FROM services WHERE is_active = 1 ORDER BY category, price")
    else:
        cursor.execute("SELECT * FROM services ORDER BY category, price")
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        try:
            d["translations"] = json.loads(d.get("translations") or "{}")
        except Exception:
            d["translations"] = {}
        results.append(d)
    return results

@app.post("/api/services")
def create_service(data: ServiceCreate):
    conn = get_db()
    cursor = conn.cursor()
    safe_name = sanitize_text(data.name)
    safe_desc = sanitize_text(data.description)
    tr_obj = auto_translate_service(safe_name, safe_desc)
    tr_json = json.dumps(tr_obj, ensure_ascii=False)
    cursor.execute("""
    INSERT INTO services (name, category, price, duration_minutes, description, is_active, translations)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (safe_name, sanitize_text(data.category), data.price, data.duration_minutes, safe_desc, data.is_active, tr_json))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return {"id": new_id, "status": "created", "translations": tr_obj}

@app.put("/api/services/{service_id}")
def update_service(service_id: int, data: ServiceCreate):
    conn = get_db()
    cursor = conn.cursor()
    safe_name = sanitize_text(data.name)
    safe_desc = sanitize_text(data.description)
    tr_obj = auto_translate_service(safe_name, safe_desc)
    tr_json = json.dumps(tr_obj, ensure_ascii=False)
    cursor.execute("""
    UPDATE services SET
        name = ?, category = ?, price = ?, duration_minutes = ?, description = ?, is_active = ?, translations = ?
    WHERE id = ?
    """, (safe_name, sanitize_text(data.category), data.price, data.duration_minutes, safe_desc, data.is_active, tr_json, service_id))
    conn.commit()
    conn.close()
    return {"status": "ok", "translations": tr_obj}

@app.delete("/api/services/{service_id}")
def delete_service(service_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM services WHERE id = ?", (service_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

@app.get("/api/clients")
def get_clients():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT c.*,
           COUNT(a.id) as visits_count,
           COALESCE(SUM(CASE WHEN a.status = 'completed' THEN a.total_price ELSE 0 END), 0) as total_spent,
           MAX(a.date) as last_visit
    FROM clients c
    LEFT JOIN appointments a ON a.client_phone = c.phone
    GROUP BY c.id
    ORDER BY c.name
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/clients")
def create_client(data: ClientCreate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO clients (name, phone, instagram, notes, points, vip_tier, unlocked_emojis, created_at)
    VALUES (?, ?, ?, ?, 50, 'Gold VIP', '💅,✨,💖', ?)
    """, (sanitize_text(data.name), sanitize_text(data.phone), sanitize_text(data.instagram), sanitize_text(data.notes), datetime.now().isoformat()))
    conn.commit()
    cid = cursor.lastrowid
    conn.close()
    return {"id": cid, "status": "created"}

@app.put("/api/clients/{client_id}")
def update_client(client_id: int, data: ClientCreate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE clients SET name = ?, phone = ?, instagram = ?, notes = ?
    WHERE id = ?
    """, (sanitize_text(data.name), sanitize_text(data.phone), sanitize_text(data.instagram), sanitize_text(data.notes), client_id))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.delete("/api/clients/{client_id}")
def delete_client(client_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

@app.post("/api/clients/{client_id}/toggle-vip")
def toggle_client_vip(client_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COALESCE(is_vip, 0) FROM clients WHERE id = ?", (client_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Клієнта не знайдено")
    current_vip = row[0]
    new_vip = 1 if current_vip == 0 else 0
    new_tier = "Diamond VIP 👑" if new_vip == 1 else "Standard"
    cursor.execute("UPDATE clients SET is_vip = ?, vip_tier = ? WHERE id = ?", (new_vip, new_tier, client_id))
    conn.commit()
    conn.close()
    return {"status": "ok", "is_vip": new_vip, "vip_tier": new_tier}

@app.get("/api/appointments")
def get_appointments(date_str: Optional[str] = None, month_str: Optional[str] = None):
    conn = get_db()
    cursor = conn.cursor()
    if date_str:
        cursor.execute("SELECT * FROM appointments WHERE date = ? ORDER BY time ASC", (date_str,))
    elif month_str:
        cursor.execute("SELECT * FROM appointments WHERE date LIKE ? ORDER BY date ASC, time ASC", (f"{month_str}%",))
    else:
        cursor.execute("SELECT * FROM appointments ORDER BY date DESC, time ASC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/appointments")
def create_appointment(data: AppointmentCreate):
    conn = get_db()
    cursor = conn.cursor()

    safe_name = sanitize_text(data.client_name)
    safe_phone = sanitize_text(data.client_phone)
    safe_notes = sanitize_text(data.notes)

    cursor.execute("SELECT id FROM clients WHERE phone = ?", (safe_phone,))
    client_row = cursor.fetchone()
    if client_row:
        client_id = client_row[0]
    else:
        cursor.execute("INSERT INTO clients (name, phone, points, vip_tier, unlocked_emojis, created_at) VALUES (?, ?, 50, 'Gold VIP', '💅,✨,💖', ?)",
                       (safe_name, safe_phone, datetime.now().isoformat()))
        client_id = cursor.lastrowid

    end_time = add_minutes(data.time, data.duration_minutes)

    cursor.execute("""
    INSERT INTO appointments (client_id, client_name, client_phone, service_names, date, time, end_time, total_price, status, payment_method, notes, source, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', ?, ?, ?, ?)
    """, (client_id, safe_name, safe_phone, data.service_names, data.date, data.time, end_time, data.total_price, data.payment_method or 'cash', safe_notes, data.source, datetime.now().isoformat()))

    conn.commit()
    aid = cursor.lastrowid
    conn.close()
    return {"id": aid, "status": "created"}

@app.patch("/api/appointments/{app_id}/status")
def update_appointment_status(app_id: int, status: str = Query(...), payment_method: Optional[str] = Query("cash")):
    if status not in ["pending", "confirmed", "completed", "cancelled"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM appointments WHERE id = ?", (app_id,))
    app_row = cursor.fetchone()
    if not app_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Appointment not found")

    old_status = app_row["status"]
    cursor.execute("UPDATE appointments SET status = ?, payment_method = ? WHERE id = ?", (status, payment_method, app_id))

    if status == "completed" and old_status != "completed":
        cursor.execute("SELECT id FROM transactions WHERE appointment_id = ?", (app_id,))
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO transactions (type, category, amount, date, payment_method, appointment_id, description, created_at)
            VALUES ('income', 'Послуги', ?, ?, ?, ?, ?, ?)
            """, (app_row["total_price"], app_row["date"], payment_method, app_id, f"Візит: {app_row['client_name']} ({app_row['service_names']})", datetime.now().isoformat()))

        # Award 50 bonus points to verified client
        cursor.execute("UPDATE clients SET points = COALESCE(points, 0) + 50 WHERE phone = ?", (app_row["client_phone"],))

    elif old_status == "completed" and status != "completed":
        cursor.execute("DELETE FROM transactions WHERE appointment_id = ?", (app_id,))
        cursor.execute("UPDATE clients SET points = MAX(0, COALESCE(points, 0) - 50) WHERE phone = ?", (app_row["client_phone"],))

    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.delete("/api/appointments/{app_id}")
def delete_appointment(app_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM appointments WHERE id = ?", (app_id,))
    cursor.execute("DELETE FROM transactions WHERE appointment_id = ?", (app_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

# --- Finance Endpoints ---
@app.get("/api/finance/summary")
def get_finance_summary(month: Optional[str] = None):
    if not month:
        month = date.today().strftime("%Y-%m")

    today_str = date.today().isoformat()
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT SUM(amount) FROM transactions WHERE type='income' AND date = ?", (today_str,))
    today_income = cursor.fetchone()[0] or 0.0
    cursor.execute("SELECT SUM(amount) FROM transactions WHERE type='expense' AND date = ?", (today_str,))
    today_expense = cursor.fetchone()[0] or 0.0

    cursor.execute("SELECT SUM(amount) FROM transactions WHERE type='income' AND date LIKE ?", (f"{month}%",))
    month_income = cursor.fetchone()[0] or 0.0
    cursor.execute("SELECT SUM(amount) FROM transactions WHERE type='expense' AND date LIKE ?", (f"{month}%",))
    month_expense = cursor.fetchone()[0] or 0.0

    cursor.execute("""
    SELECT category, SUM(amount) as total
    FROM transactions
    WHERE type='expense' AND date LIKE ?
    GROUP BY category
    ORDER BY total DESC
    """, (f"{month}%",))
    expense_categories = [dict(r) for r in cursor.fetchall()]

    cursor.execute("""
    SELECT COALESCE(payment_method, 'cash') as method, SUM(amount) as total
    FROM transactions
    WHERE type='income' AND date LIKE ?
    GROUP BY payment_method
    ORDER BY total DESC
    """, (f"{month}%",))
    income_by_method = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {
        "today": {
            "income": today_income,
            "expense": today_expense,
            "profit": today_income - today_expense
        },
        "month": {
            "income": month_income,
            "expense": month_expense,
            "profit": month_income - month_expense
        },
        "expense_categories": expense_categories,
        "income_by_method": income_by_method,
        "selected_month": month
    }

@app.get("/api/finance/transactions")
def get_transactions(month: Optional[str] = None):
    conn = get_db()
    cursor = conn.cursor()
    if month:
        cursor.execute("SELECT * FROM transactions WHERE date LIKE ? ORDER BY date DESC, id DESC", (f"{month}%",))
    else:
        cursor.execute("SELECT * FROM transactions ORDER BY date DESC, id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/finance/transactions")
def add_transaction(data: TransactionCreate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO transactions (type, category, amount, date, payment_method, description, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (data.type, sanitize_text(data.category), data.amount, data.date, data.payment_method or 'cash', sanitize_text(data.description), datetime.now().isoformat()))
    conn.commit()
    tid = cursor.lastrowid
    conn.close()
    return {"id": tid, "status": "created"}

@app.delete("/api/finance/transactions/{t_id}")
def delete_transaction(t_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM transactions WHERE id = ?", (t_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

# --- VIP Client Club & Loyalty Endpoints ---

@app.post("/api/client/avatar")
def update_client_avatar(data: ClientAvatarUpdate):
    conn = get_db()
    cursor = conn.cursor()
    phone_clean = sanitize_text(data.phone)
    cursor.execute("UPDATE clients SET avatar_url = ? WHERE phone = ? OR phone LIKE ?", (data.avatar_url, phone_clean, f"%{phone_clean[-9:]}%"))
    conn.commit()
    conn.close()
    return {"status": "ok", "avatar_url": data.avatar_url}

@app.post("/api/client/login")
def client_login(data: ClientLoginRequest):
    conn = get_db()
    cursor = conn.cursor()

    phone_clean = sanitize_text(data.phone)
    safe_name = sanitize_text(data.name)
    safe_insta = sanitize_text(data.instagram)
    safe_avatar = data.avatar_url or ''

    cursor.execute("SELECT * FROM clients WHERE phone LIKE ? OR phone LIKE ?", (f"%{phone_clean}%", f"%{phone_clean[-9:]}%"))
    client = cursor.fetchone()

    if not client:
        cursor.execute("SELECT * FROM appointments WHERE client_phone LIKE ? OR client_phone LIKE ? ORDER BY id DESC LIMIT 1", (f"%{phone_clean}%", f"%{phone_clean[-9:]}%"))
        any_app = cursor.fetchone()
        client_name = safe_name or (any_app["client_name"] if any_app else "Клієнтка")
        
        cursor.execute("""
        INSERT INTO clients (name, phone, instagram, avatar_url, points, vip_tier, unlocked_emojis, created_at)
        VALUES (?, ?, ?, ?, 50, 'Gold VIP', '💅,✨,💖', ?)
        """, (client_name, phone_clean, safe_insta, safe_avatar, datetime.now().isoformat()))
        conn.commit()
        cursor.execute("SELECT * FROM clients WHERE phone = ?", (phone_clean,))
        client = cursor.fetchone()
    else:
        # Update instagram / avatar / name if provided and not already present
        up_fields = []
        up_params = []
        if safe_name and client["name"] in ("Клієнтка", ""):
            up_fields.append("name = ?")
            up_params.append(safe_name)
        if safe_insta and not client["instagram"]:
            up_fields.append("instagram = ?")
            up_params.append(safe_insta)
        if safe_avatar and not client["avatar_url"]:
            up_fields.append("avatar_url = ?")
            up_params.append(safe_avatar)
        if up_fields:
            up_params.append(client["id"])
            cursor.execute(f"UPDATE clients SET {', '.join(up_fields)} WHERE id = ?", up_params)
            conn.commit()
            cursor.execute("SELECT * FROM clients WHERE id = ?", (client["id"],))
            client = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) FROM appointments WHERE (client_phone = ? OR client_phone LIKE ?) AND status = 'completed'", (client["phone"], f"%{client['phone'][-9:]}%"))
    completed_count = cursor.fetchone()[0]

    conn.close()
    return {
        "status": "ok",
        "client": dict(client),
        "completed_count": completed_count
    }

@app.get("/api/client/profile")
def get_client_profile(phone: str):
    conn = get_db()
    cursor = conn.cursor()
    safe_phone = sanitize_text(phone)
    cursor.execute("SELECT * FROM clients WHERE phone = ? OR phone LIKE ?", (safe_phone, f"%{safe_phone[-9:]}%"))
    client = cursor.fetchone()
    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Client not found")

    cursor.execute("SELECT * FROM appointments WHERE client_phone = ? OR client_phone LIKE ? ORDER BY date DESC, time DESC", (client["phone"], f"%{client['phone'][-9:]}%"))
    appointments = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {
        "client": dict(client),
        "appointments": appointments
    }

@app.post("/api/client/redeem")
def redeem_reward(data: RedeemRequest):
    conn = get_db()
    cursor = conn.cursor()
    safe_phone = sanitize_text(data.phone)
    cursor.execute("SELECT points, unlocked_emojis FROM clients WHERE phone = ? OR phone LIKE ?", (safe_phone, f"%{safe_phone[-9:]}%"))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Client not found")

    cur_points = row["points"] or 0
    if cur_points < data.points_cost:
        conn.close()
        raise HTTPException(status_code=400, detail="Недостатньо балів для цього бонусу")

    emojis = (row["unlocked_emojis"] or "").split(",")
    if data.item_id not in emojis:
        emojis.append(data.item_id)
    new_emojis_str = ",".join(filter(None, emojis))

    new_points = cur_points - data.points_cost
    cursor.execute("UPDATE clients SET points = ?, unlocked_emojis = ? WHERE phone = ? OR phone LIKE ?", (new_points, new_emojis_str, safe_phone, f"%{safe_phone[-9:]}%"))
    conn.commit()
    conn.close()
    return {"status": "ok", "points": new_points, "unlocked_emojis": new_emojis_str}


class VipRewardCreate(BaseModel):
    icon: Optional[str] = "💎"
    title: str = Field(..., min_length=2, max_length=120)
    description: Optional[str] = ""
    cost: int = Field(..., gt=0)
    reward_type: Optional[str] = "discount"

@app.get("/api/vip/rewards")
def get_vip_rewards():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vip_rewards WHERE is_active = 1 ORDER BY cost ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/vip/rewards")
def create_vip_reward(data: VipRewardCreate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO vip_rewards (icon, title, description, cost, reward_type)
    VALUES (?, ?, ?, ?, ?)
    """, (sanitize_text(data.icon), sanitize_text(data.title), sanitize_text(data.description), data.cost, data.reward_type or 'discount'))
    conn.commit()
    rid = cursor.lastrowid
    conn.close()
    return {"id": rid, "status": "created"}

@app.put("/api/vip/rewards/{reward_id}")
def update_vip_reward(reward_id: int, data: VipRewardCreate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE vip_rewards SET
        icon = ?, title = ?, description = ?, cost = ?, reward_type = ?
    WHERE id = ?
    """, (sanitize_text(data.icon), sanitize_text(data.title), sanitize_text(data.description), data.cost, data.reward_type or 'discount', reward_id))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.delete("/api/vip/rewards/{reward_id}")
def delete_vip_reward(reward_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vip_rewards WHERE id = ?", (reward_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

@app.get("/api/reviews")
def get_reviews():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reviews ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/reviews")
def add_review(data: ReviewCreate):
    conn = get_db()
    cursor = conn.cursor()
    today_str = date.today().isoformat()
    safe_name = sanitize_text(data.client_name)
    safe_phone = sanitize_text(data.client_phone)
    safe_comment = sanitize_text(data.comment)

    cursor.execute("""
    INSERT INTO reviews (client_name, client_phone, rating, comment, emojis, date)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (safe_name, safe_phone, data.rating, safe_comment, data.emojis or '', today_str))

    cursor.execute("UPDATE clients SET points = COALESCE(points, 0) + 20 WHERE phone = ? OR phone LIKE ?", (safe_phone, f"%{safe_phone[-9:]}%"))
    conn.commit()
    conn.close()
    return {"status": "created"}

# --- Public Online Booking Endpoints ---

@app.get("/api/public/info")
def get_public_info():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT master_name, studio_name, phone, instagram, telegram, address, currency, about, bizum_phone, paypal_link, card_ua, card_es, accept_bizum, accept_card, accept_paypal, accept_cash, master_avatar FROM settings WHERE id = 1")
    settings = dict(cursor.fetchone() or {})
    cursor.execute("SELECT id, name, category, price, duration_minutes, description, translations FROM services WHERE is_active = 1 ORDER BY category, price")
    services = []
    for r in cursor.fetchall():
        d = dict(r)
        try:
            d["translations"] = json.loads(d.get("translations") or "{}")
        except Exception:
            d["translations"] = {}
        services.append(d)
    conn.close()
    return {"settings": settings, "services": services}

@app.get("/api/public/available-slots")
def get_available_slots(date_str: str, duration: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT work_start, work_end, slot_step FROM settings WHERE id = 1")
    s = cursor.fetchone()
    if not s:
        conn.close()
        return []

    work_start_m = time_to_minutes(s["work_start"])
    work_end_m = time_to_minutes(s["work_end"])
    slot_step = s["slot_step"] or 30

    cursor.execute("SELECT time, end_time FROM appointments WHERE date = ? AND status != 'cancelled'", (date_str,))
    bookings = cursor.fetchall()
    conn.close()

    busy_intervals = []
    for b in bookings:
        busy_intervals.append((time_to_minutes(b["time"]), time_to_minutes(b["end_time"])))

    now = datetime.now()
    is_today = (date_str == date.today().isoformat())
    current_minutes = now.hour * 60 + now.minute

    available_slots = []
    current_slot = work_start_m
    while current_slot + duration <= work_end_m:
        slot_end = current_slot + duration

        if is_today and current_slot <= current_minutes + 15:
            current_slot += slot_step
            continue

        collides = False
        for b_start, b_end in busy_intervals:
            if not (slot_end <= b_start or current_slot >= b_end):
                collides = True
                break

        if not collides:
            h = current_slot // 60
            m = current_slot % 60
            available_slots.append(f"{h:02d}:{m:02d}")

        current_slot += slot_step

    return available_slots

@app.post("/api/public/book")
def public_book(data: PublicBookingRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"

    # Anti-bot spam rate limiter (max 10 bookings per 10 minutes)
    if not check_rate_limit(f"book_{client_ip}", max_requests=10, window_seconds=600):
        raise HTTPException(status_code=429, detail="Забагато запитів з вашого пристрою. Задля безпеки спробуйте через кілька хвилин.")

    safe_name = sanitize_text(data.client_name)
    safe_phone = sanitize_text(data.client_phone)
    safe_notes = sanitize_text(data.notes)

    conn = get_db()
    cursor = conn.cursor()

    end_time = add_minutes(data.time, data.total_duration)
    req_start = time_to_minutes(data.time)
    req_end = time_to_minutes(end_time)

    cursor.execute("SELECT time, end_time FROM appointments WHERE date = ? AND status != 'cancelled'", (data.date,))
    existing = cursor.fetchall()
    for b in existing:
        b_start = time_to_minutes(b["time"])
        b_end = time_to_minutes(b["end_time"])
        if not (req_end <= b_start or req_start >= b_end):
            conn.close()
            raise HTTPException(status_code=400, detail="На жаль, цей час вже зайняли. Будь ласка, оберіть інший час.")

    cursor.execute("SELECT id FROM clients WHERE phone = ?", (safe_phone,))
    client_row = cursor.fetchone()
    if client_row:
        client_id = client_row[0]
        cursor.execute("UPDATE clients SET name = ? WHERE id = ?", (safe_name, client_id))
    else:
        cursor.execute("INSERT INTO clients (name, phone, points, vip_tier, unlocked_emojis, created_at) VALUES (?, ?, 50, 'Gold VIP', '💅,✨,💖', ?)",
                       (safe_name, safe_phone, datetime.now().isoformat()))
        client_id = cursor.lastrowid

    cursor.execute("""
    INSERT INTO appointments (client_id, client_name, client_phone, service_names, date, time, end_time, total_price, status, payment_method, notes, source, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', 'cash', ?, 'client', ?)
    """, (client_id, safe_name, safe_phone, data.service_names, data.date, data.time, end_time, data.total_price, safe_notes, datetime.now().isoformat()))

    conn.commit()
    aid = cursor.lastrowid
    conn.close()

    return {"status": "success", "appointment_id": aid}

# --- Static frontend routing ---
@app.get("/")
def serve_index():
    return FileResponse("static/index.html")

@app.get("/book")
def serve_book():
    return FileResponse("static/book.html")

@app.get("/club")
@app.get("/client")
def serve_client_club():
    return FileResponse("static/client.html")

@app.get("/download/ios-profile")
def download_ios_profile():
    icon_b64 = ""
    try:
        with open("static/icon-192.png", "rb") as f:
            icon_b64 = base64.b64encode(f.read()).decode("utf-8")
    except Exception:
        pass
    
    mobileconfig = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>FullScreen</key>
            <true/>
            <key>Icon</key>
            <data>{icon_b64}</data>
            <key>IsRemovable</key>
            <true/>
            <key>Label</key>
            <string>Natali Nails</string>
            <key>PayloadDescription</key>
            <string>Natali Nails Privé Web App</string>
            <key>PayloadDisplayName</key>
            <string>Natali Nails</string>
            <key>PayloadIdentifier</key>
            <string>com.natalinails.webclip</string>
            <key>PayloadType</key>
            <string>com.apple.webClip.managed</string>
            <key>PayloadUUID</key>
            <string>c734914a-1111-4444-a111-000000000001</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>URL</key>
            <string>https://natali-nails.onrender.com</string>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Natali Nails Privé</string>
    <key>PayloadIdentifier</key>
    <string>com.natalinails.profile</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>c734914a-2222-4444-b222-000000000002</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>"""
    return Response(content=mobileconfig, media_type="application/x-apple-aspen-config", headers={
        "Content-Disposition": 'attachment; filename="NataliNails.mobileconfig"'
    })

app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
