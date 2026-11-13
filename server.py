import re
import os
import json
import base64
import sqlite3
import secrets
import html
import time
from datetime import datetime, timedelta, date
from typing import List, Optional, Dict, Union
from fastapi import FastAPI, HTTPException, Query, Request, Response, Depends, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

DB_FILE = "app.db"

app = FastAPI(title="Natali Nails - Secure Beauty CRM")

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

    # Ensure whatsapp column exists in settings
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN whatsapp TEXT DEFAULT ''")
    except Exception:
        pass

    # Ensure facebook column exists in settings
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN facebook TEXT DEFAULT ''")
    except Exception:
        pass

    # Ensure working_days column exists in settings
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN working_days TEXT DEFAULT '1,2,3,4,5,6'")
    except Exception:
        pass

    # Ensure schedule_json column exists in settings
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN schedule_json TEXT DEFAULT ''")
    except Exception:
        pass

    # Ensure card_ua and card_es and session_token columns exist in settings
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN card_ua TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN card_es TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN session_token TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN bizum_phone TEXT DEFAULT '+34 612 345 678'")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN paypal_link TEXT DEFAULT 'paypal.me/nailstudio'")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN accept_bizum INTEGER DEFAULT 1")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN accept_card INTEGER DEFAULT 1")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN accept_paypal INTEGER DEFAULT 1")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN accept_cash INTEGER DEFAULT 1")
    except Exception:
        pass

    # Ensure initial settings row 1 exists
    try:
        cursor.execute("SELECT id FROM settings WHERE id = 1")
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO settings (id, master_name, studio_name, phone, address, currency, work_start, work_end, working_days, slot_step, bizum_phone, paypal_link)
            VALUES (1, 'Natali', 'Natali Nails', '+34612345678', 'м. Київ, вул. Хрещатик, 15 (каб. 24)', '€', '10:00', '20:00', '1,2,3,4,5,6', 30, '+34 612 345 678', 'paypal.me/natalinails')
            """)
    except Exception:
        pass

    # Create chat_messages table if not exists
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        appointment_id INTEGER,
        client_phone TEXT NOT NULL,
        sender TEXT NOT NULL,
        sender_name TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at TEXT NOT NULL,
        is_read INTEGER DEFAULT 0
    )
    """)

    # Ensure client password column exists in clients
    try:
        cursor.execute("ALTER TABLE clients ADD COLUMN password TEXT DEFAULT ''")
    except Exception:
        pass

    # Ensure client social & notes columns exist in clients
    for c_col in ['telegram', 'whatsapp', 'facebook']:
        try:
            cursor.execute(f"ALTER TABLE clients ADD COLUMN {c_col} TEXT DEFAULT ''")
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

    # Initialize schedule_json in settings if empty
    try:
        cursor.execute("SELECT schedule_json FROM settings WHERE id = 1")
        s_row = cursor.fetchone()
        if s_row and (not s_row["schedule_json"] or s_row["schedule_json"] == ""):
            init_schedule = json.dumps({
                "1": {"active": True, "start": "10:00", "end": "20:00"},
                "2": {"active": True, "start": "10:00", "end": "20:00"},
                "3": {"active": True, "start": "10:00", "end": "20:00"},
                "4": {"active": True, "start": "10:00", "end": "20:00"},
                "5": {"active": True, "start": "10:00", "end": "20:00"},
                "6": {"active": True, "start": "10:00", "end": "18:00"},
                "0": {"active": False, "start": "10:00", "end": "18:00"}
            }, ensure_ascii=False)
            cursor.execute("UPDATE settings SET schedule_json = ? WHERE id = 1", (init_schedule,))
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

    # Seed initial rewards and extra emojis if missing
    try:
        extra_rewards = [
            ('👑', 'Золота VIP-Корона', 'Ексклюзивний смайлик корони для ваших відгуків', 30, 'emoji'),
            ('💎', 'Діамантове сяйво', 'Смайлик діаманту поруч з вашим ім’ям', 25, 'emoji'),
            ('🔥', 'Вельветовий вогник', 'Смайлик тренду Velvet Nails', 20, 'emoji'),
            ('🦋', 'Метелик естетики', 'Ніжний трендовий метелик для відгуків', 15, 'emoji'),
            ('🍸', 'Prosecco & Коктейль', 'Естетичний смайлик настрою у студії', 20, 'emoji'),
            ('💄', 'Французький шик', 'Смайлик для витонченого манікюру', 20, 'emoji'),
            ('🎀', 'Рожевий бантик', 'Трендовий Coquette бантик для ваших відгуків', 15, 'emoji'),
            ('💋', 'Полуничний поцілунок', 'Яскравий смайлик краси', 20, 'emoji'),
            ('🍓', 'Соковита полуниця', 'Свіжий ягідний акцент', 15, 'emoji'),
            ('🌹', 'Оксамитова троянда', 'Символ витонченості та ніжності', 20, 'emoji'),
            ('💫', 'Магічні зірочки', 'Сяйво зірок на ваших нігтиках', 15, 'emoji'),
            ('🕊️', 'Pure Luxury', 'Преміальний білий символ спокою', 25, 'emoji'),
            ('🪄', 'Чарівний манікюр', 'Магічний пензлик майстра', 20, 'emoji'),
            ('🧁', 'Солодкий десерт', 'Смайлик компліменту', 15, 'emoji'),
            ('🦄', 'Єдиноріг тренд', 'Казковий смайлик сяйва', 25, 'emoji'),
            ('🔮', 'Cat Eye кристал', 'Загадковий перелив котячого ока', 20, 'emoji'),
            ('🌙', 'Місячне сяйво', 'Місячний відблиск', 15, 'emoji'),
            ('⭐', 'Зірка стилю', 'Смайлик для топ-клієнток', 15, 'emoji'),
            ('🐆', 'Леопардовий тренд', 'Дикий та стильний леопардовий принт', 25, 'emoji'),
            ('🤍', 'Біле золото Clean Girl', 'Естетика чистоти та натурального сяйва', 20, 'emoji'),
            ('🖤', 'Чорний вельвет', 'Глибокий стильний чорний оксамит', 20, 'emoji'),
            ('☕', 'Кава & Prosecco', 'Улюблений напій у студії безкоштовно', 15, 'gift'),
            ('🏷️', 'Знижка 1.50€ на візит', 'Приємна знижка на наступну процедуру', 100, 'discount'),
            ('🏷️', 'Знижка 2.50€ на візит', 'Супер-знижка на будь-який комплекс', 150, 'discount'),
            ('🌸', 'SPA-догляд для рук', 'Холодний парафін + скрабування в подарунок', 80, 'service')
        ]
        for r_icon, r_title, r_desc, r_cost, r_type in extra_rewards:
            cursor.execute("SELECT id FROM vip_rewards WHERE title = ? OR icon = ?", (r_title, r_icon))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO vip_rewards (icon, title, description, cost, reward_type) VALUES (?, ?, ?, ?, ?)", (r_icon, r_title, r_desc, r_cost, r_type))
    except Exception:
        pass

            # Enforce Euro currency and clean branding
    try:
        cursor.execute("UPDATE settings SET currency = '€', studio_name = 'Natali Nails'")
    except Exception:
        pass

    # Ensure all services have full multilingual translations and Euro prices
    try:
        services_seed = [{'id': 9, 'name': 'Clean Girl: Milky Nude (Комплекс)', 'category': 'Комплекс', 'price': 35.0, 'duration_minutes': 90, 'description': 'Зняття + комбі-манікюр + зміцнення + трендовий напівпрозорий молочний/нюд глянець', 'translations': {'name': {'uk': 'Clean Girl: Milky Nude (Комплекс)', 'en': 'Clean Girl: Milky Nude (Full Complex)', 'es': 'Clean Girl: Milky Nude (Completo)', 'va': 'Clean Girl: Milky Nude (Complet)', 'de': 'Clean Girl: Milky Nude (Komplex)', 'ru': 'Clean Girl: Milky Nude (Комплекс)'}, 'description': {'uk': 'Зняття + комбі-манікюр + зміцнення + трендовий напівпрозорий молочний/нюд глянець', 'en': 'Removal + Russian combi-manicure + strengthening + trending sheer milky/nude gloss', 'es': 'Retirada + manicura combinada + refuerzo + brillo lechoso/nude en tendencia', 'va': 'Retirada + manicura combinada + reforç + brillantor lletosa/nude en tendència', 'de': 'Entfernung + Combi-Maniküre + Verstärkung + trendiger milchiger/nude Glanz', 'ru': 'Снятие + комби-маникюр + укрепление + трендовый полупрозрачный молочный/нюд глянец'}}}, {'id': 10, 'name': 'Японський еко-манікюр (P.Shine / Masura)', 'category': 'Манікюр', 'price': 25.0, 'duration_minutes': 50, 'description': 'Оздоровлення нігтів без покриття. Втирання бджолиного воску, діамантовий натуральний блиск', 'translations': {'name': {'uk': 'Японський еко-манікюр (P.Shine / Masura)', 'en': 'Japanese Eco-Manicure (P.Shine / Masura)', 'es': 'Manicura ecológica japonesa (P.Shine / Masura)', 'va': 'Manicura ecològica japonesa (P.Shine / Masura)', 'de': 'Japanische Öko-Maniküre (P.Shine / Masura)', 'ru': 'Японский эко-маникюр (P.Shine / Masura)'}, 'description': {'uk': 'Оздоровлення нігтів без покриття. Втирання бджолиного воску, діамантовий натуральний блиск', 'en': 'Nail restoration without polish. Natural beeswax buffing, brilliant healthy shine', 'es': 'Recuperación natural sin esmalte. Pulido con cera de abeja y brillo diamante natural', 'va': "Recuperació natural sense esmalt. Polit amb cera d'abelles i brillantor diamant natural", 'de': 'Natürliche Nagelregeneration ohne Lack. Bienenwachs-Politur, natürlicher Diamantglanz', 'ru': 'Оздоровление ногтей без покрытия. Втирание пчелиного воска, бриллиантовый натуральный блеск'}}}, {'id': 11, 'name': 'Трендовий Micro-French / Оксамитовий френч', 'category': 'Дизайн', 'price': 38.0, 'duration_minutes': 100, 'description': 'Комплекс з найтоншим витонченим френчем або оксамитовим акцентом', 'translations': {'name': {'uk': 'Трендовий Micro-French / Оксамитовий френч', 'en': 'Trendy Micro-French / Velvet French', 'es': 'Micro-French de tendencia / Francesa terciopelo', 'va': 'Micro-French de tendència / Francesa vellut', 'de': 'Trendiger Micro-French / Samt French', 'ru': 'Трендовый Micro-French / Бархатный френч'}, 'description': {'uk': 'Комплекс з найтоншим витонченим френчем або оксамитовим акцентом', 'en': 'Full complex with ultra-thin micro-french or velvet texture accent', 'es': 'Completo con manicura francesa micro ultra fina o acento terciopelo', 'va': 'Complet amb manicura francesa micro ultra fina o accent de vellut', 'de': 'Komplex mit hauchdünnem Micro-French oder samtigem Samt-Akzent', 'ru': 'Комплекс с тончайшим изящным френчем или бархатным акцентом'}}}, {'id': 12, 'name': 'Velvet Cat Eye (Оксамитове котяче око)', 'category': 'Дизайн', 'price': 36.0, 'duration_minutes': 90, 'description': 'Багатошаровий магнітний відблиск з ефектом м’якого шовку/сатину', 'translations': {'name': {'uk': 'Velvet Cat Eye (Оксамитове котяче око)', 'en': 'Velvet Cat Eye Gel Polish', 'es': 'Esmaltado Ojo de Gato Terciopelo (Cat Eye)', 'va': 'Ull de Gat Vellut (Cat Eye)', 'de': 'Velvet Cat Eye Maniküre', 'ru': 'Бархатный кошачий глаз (Cat Eye)'}, 'description': {'uk': 'Багатошаровий магнітний відблиск з ефектом м’якого шовку/сатину', 'en': 'Multi-dimensional magnetic light reflection with soft silk/satin velvet effect', 'es': 'Reflejo magnético multidimensional con efecto terciopelo sedoso/satén', 'va': 'Reflex magnètic multidimensional amb efecte vellut sedós/satí', 'de': 'Mehrdimensionaler magnetischer Schimmer mit weichem Seiden-/Satin-Effekt', 'ru': 'Многослойный магнитный блик с эффектом мягкого шелка/сатина'}}}, {'id': 13, 'name': 'Гігієнічний апаратний манікюр + догляд', 'category': 'Манікюр', 'price': 20.0, 'duration_minutes': 45, 'description': 'Бездоганна чистка кутикули, форма, сироватка та доглядовий масаж', 'translations': {'name': {'uk': 'Гігієнічний апаратний манікюр + догляд', 'en': 'Hardware / Russian Manicure + Care', 'es': 'Manicura combinada / rusa con cuidado nutritivo', 'va': 'Manicura combinada / russa amb cura nutritiva', 'de': 'Kombinierte Apparat-Maniküre + Pflege', 'ru': 'Аппаратный / комбинированный маникюр + уход'}, 'description': {'uk': 'Бездоганна чистка кутикули, форма, сироватка та доглядовий масаж', 'en': 'Flawless cuticle clean, nail shaping, nourishing serum and caring mini-massage', 'es': 'Limpieza perfecta de cutícula, limado, sérum nutritivo y masaje suave', 'va': 'Neteja perfecta de cutícula, llimat, sèrum nutritiu i massatge suau', 'de': 'Makellose Nagelhautreinigung, Formgebung, Pflegeserum und Handmassage', 'ru': 'Безупречная чистка кутикулы, форма, сыворотка и уходовый массаж'}}}, {'id': 14, 'name': 'Нарощування та моделювання нігтів', 'category': 'Нарощування', 'price': 45.0, 'duration_minutes': 140, 'description': 'Правильна архітектура, довжина 1-3, манікюр та однотонний нюд', 'translations': {'name': {'uk': 'Нарощування та моделювання нігтів', 'en': 'Nail Extensions & Sculpting (Gel / Polygel)', 'es': 'Esculpido y extensiones de uñas (Gel)', 'va': "Esculpit i extensions d'ungles (Gel)", 'de': 'Nagelmodellage & Verlängerung (Gel / Polygel)', 'ru': 'Наращивание и моделирование ногтей'}, 'description': {'uk': 'Правильна архітектура, довжина 1-3, манікюр та однотонний нюд', 'en': 'Perfect nail architecture sculpting, length 1-3, manicure and solid nude gel', 'es': 'Esculpido y arquitectura perfecta, longitud 1-3, manicura y tono nude', 'va': 'Esculpit i arquitectura perfecta, longitud 1-3, manicura i to nude', 'de': 'Perfekte Nagelmodellage & Architektur, Länge 1-3, Maniküre und Nude-Gel', 'ru': 'Правильная архитектура, длина 1-3, маникюр и однотонный нюд'}}}, {'id': 15, 'name': 'Корекція нарощених нігтів', 'category': 'Нарощування', 'price': 35.0, 'duration_minutes': 110, 'description': 'Відновлення архітектури нігтів, підняття клюючих, зміцнення та колір', 'translations': {'name': {'uk': 'Корекція нарощених нігтів', 'en': 'Nail Extension Refill / Infill Correction', 'es': 'Relleno y corrección de extensiones de uñas', 'va': "Farciment i correcció d'extensions d'ungles", 'de': 'Nagelkorrektur / Auffüllen der Modellage', 'ru': 'Коррекция нарощенных ногтей'}, 'description': {'uk': 'Відновлення архітектури нігтів, підняття клюючих, зміцнення та колір', 'en': 'Arch restoration, lifting correction, strengthening and fresh solid color', 'es': 'Restauración de arquitectura, corrección, refuerzo y color uniforme', 'va': "Restauració d'arquitectura, correcció, reforç i color uniforme", 'de': 'Korrektur der Nagelarchitektur, Verstärkung und neue Farbe', 'ru': 'Восстановление архитектуры ногтей, поднятие клюющих, укрепление и цвет'}}}, {'id': 16, 'name': 'SPA-догляд для рук (холодний парафін)', 'category': 'Догляд', 'price': 12.0, 'duration_minutes': 25, 'description': 'Глибоке живлення та шовковистість шкіри ручок після манікюру', 'translations': {'name': {'uk': 'SPA-догляд для рук (холодний парафін)', 'en': 'Cold Paraffin Hand SPA Therapy', 'es': 'SPA de manos con parafina fría', 'va': 'SPA de mans amb parafina freda', 'de': 'Hand-SPA Kaltparaffin-Behandlung', 'ru': 'SPA-уход для рук (холодный парафин)'}, 'description': {'uk': 'Глибоке живлення та шовковистість шкіри ручок після манікюру', 'en': 'Deep skin nourishment and velvety smoothness with cold paraffin therapy', 'es': 'Nutrición profunda y piel aterciopelada con parafina fría tras la manicura', 'va': 'Nutrició profunda i pell vellutada amb parafina freda després de la manicura', 'de': 'Tiefenwirksame Pflege und samtweiche Haut mit Kaltparaffin-Therapie', 'ru': 'Глубокое питание и шелковистость кожи ручек после маникюра'}}}, {'id': 17, 'name': 'Ремонт 1 нігтя / нарощування кутика', 'category': 'Догляд', 'price': 4.0, 'duration_minutes': 15, 'description': 'Ремонт тріщини шовком або донарощування зламаного нігтика', 'translations': {'name': {'uk': 'Ремонт 1 нігтя / нарощування кутика', 'en': 'Nail Repair (1 nail) / Corner Sculpting', 'es': 'Reparación de 1 uña / reconstrucción de esquina', 'va': "Reparació d'1 ungla / reconstrucció de cantó", 'de': 'Reparatur von 1 Nagel / Kantennachbildung', 'ru': 'Ремонт 1 ногтя / наращивание уголка'}, 'description': {'uk': 'Ремонт тріщини шовком або донарощування зламаного нігтика', 'en': 'Silk wrap crack repair or broken nail tip sculpting extension', 'es': 'Reparación de fisura con seda o reconstrucción de uña rota', 'va': "Reparació de fissura amb seda o reconstrucció d'ungla trencada", 'de': 'Rissreparatur mit Seide oder Wiederaufbau einer abgebrochenen Nagelkante', 'ru': 'Ремонт трещины шелком или донаращивание сломанного ноготка'}}}]
        for s in services_seed:
            tr_str = json.dumps(s["translations"], ensure_ascii=False)
            cursor.execute("SELECT id FROM services WHERE id = ? OR name = ?", (s["id"], s["name"]))
            existing = cursor.fetchone()
            if existing:
                cursor.execute("""
                    UPDATE services
                    SET name = ?, category = ?, price = ?, duration_minutes = ?, description = ?, translations = ?, is_active = 1
                    WHERE id = ?
                """, (s["name"], s["category"], s["price"], s["duration_minutes"], s["description"], tr_str, existing[0]))
            else:
                cursor.execute("""
                    INSERT INTO services (id, name, category, price, duration_minutes, description, is_active, translations)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """, (s["id"], s["name"], s["category"], s["price"], s["duration_minutes"], s["description"], tr_str))
        # Remove any unwanted dummy/test services
        cursor.execute("DELETE FROM services WHERE name LIKE '%побрити%'")
    except Exception:
        pass
    # Clean Privé branding from DB settings
    try:
        cursor.execute("UPDATE settings SET studio_name = 'Natali Nails' WHERE studio_name LIKE '%Privé%' OR studio_name LIKE '%Prive%'")
    except Exception:
        pass

    # Reset old demo transactions that caused negative balance (-1700)
    try:
        cursor.execute("DELETE FROM transactions WHERE (category IN ('Матеріали', 'Дезінфекція') AND appointment_id IS NULL) OR id IN (1, 2)")
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

class AddPointsRequest(BaseModel):
    points: int = Field(..., ge=-10000, le=10000)

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
    master_name: Optional[str] = "Natali"
    studio_name: Optional[str] = "Natali Nails"
    phone: Optional[str] = "+34 600 000 000"
    instagram: Optional[str] = ""
    telegram: Optional[str] = ""
    whatsapp: Optional[str] = ""
    facebook: Optional[str] = ""
    address: Optional[str] = ""
    work_start: Optional[str] = "10:00"
    work_end: Optional[str] = "20:00"
    slot_step: Optional[int] = 30
    currency: Optional[str] = "€"
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
    working_days: Optional[str] = "1,2,3,4,5,6"
    schedule_json: Optional[str] = ""

class EditAppointmentRequest(BaseModel):
    date: str
    time: str
    duration_minutes: Optional[int] = 90
    service_names: Optional[str] = None
    total_price: Optional[float] = None
    notes: Optional[str] = ""
    status: Optional[str] = None

class SendChatMessageRequest(BaseModel):
    appointment_id: Optional[int] = None
    client_phone: str
    sender: str  # 'master' or 'client'
    sender_name: Optional[str] = "Natali"
    text: str

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

class InstagramLoginRequest(BaseModel):
    instagram: str

class ClientRegisterRequest(BaseModel):
    name: str
    phone: str
    password: str

class ClientPasswordLoginRequest(BaseModel):
    phone: str
    password: str

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
    item_id: Union[int, str]
    points_cost: Optional[int] = 0
    reward_icon: Optional[str] = None
    reward_title: Optional[str] = None

class ClientPaymentNotifyRequest(BaseModel):
    payment_method: str

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
    cursor.execute("SELECT master_name, studio_name, phone, instagram, telegram, whatsapp, facebook, address, work_start, work_end, working_days, schedule_json, slot_step, currency, about, bizum_phone, paypal_link, card_ua, card_es, accept_bizum, accept_card, accept_paypal, accept_cash, master_avatar FROM settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}

@app.post("/api/settings")
def update_settings(data: SettingsUpdate):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Check if settings row 1 exists
        cursor.execute("SELECT id FROM settings WHERE id = 1")
        if not cursor.fetchone():
            cursor.execute("""
            INSERT INTO settings (id, master_name, studio_name, phone, address, currency, work_start, work_end, working_days, slot_step, bizum_phone, paypal_link)
            VALUES (1, 'Natali', 'Natali Nails', '+34612345678', 'м. Київ, вул. Хрещатик, 15 (каб. 24)', '€', '10:00', '20:00', '1,2,3,4,5,6', 30, '+34 612 345 678', 'paypal.me/natalinails')
            """)

        cursor.execute("""
        UPDATE settings SET
            master_name = ?, studio_name = ?, phone = ?, instagram = ?,
            telegram = ?, whatsapp = ?, facebook = ?, address = ?, work_start = ?, work_end = ?,
            working_days = ?, schedule_json = COALESCE(NULLIF(?, ''), schedule_json), slot_step = ?, currency = ?, about = ?,
            bizum_phone = ?, paypal_link = ?, card_ua = ?, card_es = ?,
            accept_bizum = ?, accept_card = ?, accept_paypal = ?, accept_cash = ?,
            master_avatar = COALESCE(NULLIF(?, ''), master_avatar)
        WHERE id = 1
        """, (sanitize_text(data.master_name), sanitize_text(data.studio_name), sanitize_text(data.phone), sanitize_text(data.instagram),
              sanitize_text(data.telegram), sanitize_text(data.whatsapp or ''), sanitize_text(data.facebook or ''), sanitize_text(data.address), data.work_start, data.work_end,
              (data.working_days if data.working_days is not None else '1,2,3,4,5,6'),
              data.schedule_json or '',
              data.slot_step, data.currency, sanitize_text(data.about),
              sanitize_text(data.bizum_phone), sanitize_text(data.paypal_link),
              sanitize_text(data.card_ua), sanitize_text(data.card_es),
              data.accept_bizum, data.accept_card, data.accept_paypal, data.accept_cash,
              data.master_avatar or ''))
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
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

@app.post("/api/clients/{client_id}/add-points")
def add_client_points(client_id: int, data: AddPointsRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, points, name FROM clients WHERE id = ?", (client_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Клієнта не знайдено")
    cur_p = row["points"] if row["points"] is not None else 0
    new_points = max(0, cur_p + data.points)
    cursor.execute("UPDATE clients SET points = ? WHERE id = ?", (new_points, client_id))
    conn.commit()
    conn.close()
    return {"status": "ok", "client_id": client_id, "points": new_points}

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

    # Check if client exists by phone or by instagram without phone
    cursor.execute("SELECT id FROM clients WHERE phone = ? OR (phone = '' AND (name = ? OR instagram LIKE ?))", (safe_phone, safe_name, f"%{safe_name}%"))
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

@app.get("/api/appointments/{app_id}")
def get_appointment(app_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM appointments WHERE id = ?", (app_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Appointment not found")
    return {"status": "ok", "appointment": dict(row)}

@app.patch("/api/appointments/{app_id}/confirm")
def confirm_appointment(app_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM appointments WHERE id = ?", (app_id,))
    app_row = cursor.fetchone()
    if not app_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Appointment not found")

    cursor.execute("UPDATE appointments SET status = 'confirmed' WHERE id = ?", (app_id,))
    now_iso = datetime.now().isoformat()
    cursor.execute("""
    INSERT INTO chat_messages (appointment_id, client_phone, sender, sender_name, text, created_at, is_read)
    VALUES (?, ?, 'master', 'Natali', ?, ?, 0)
    """, (app_id, app_row["client_phone"], f"✅ Ваше замовлення на {app_row['date']} о {app_row['time']} підтверджено! Чекаю на вас у студії 💅", now_iso))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.put("/api/appointments/{app_id}")
def edit_appointment(app_id: int, data: EditAppointmentRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM appointments WHERE id = ?", (app_id,))
    app_row = cursor.fetchone()
    if not app_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Appointment not found")

    dur = data.duration_minutes or 90
    end_time = add_minutes(data.time, dur)
    service_names = sanitize_text(data.service_names or app_row["service_names"])
    total_price = float(data.total_price) if data.total_price is not None else float(app_row["total_price"])
    notes = sanitize_text(data.notes or "")
    status = data.status or app_row["status"]

    time_changed = (data.date != app_row["date"] or data.time != app_row["time"])

    cursor.execute("""
    UPDATE appointments
    SET date = ?, time = ?, end_time = ?, service_names = ?, total_price = ?, notes = ?, status = ?
    WHERE id = ?
    """, (data.date, data.time, end_time, service_names, total_price, notes, status, app_id))

    if time_changed:
        now_iso = datetime.now().isoformat()
        cursor.execute("""
        INSERT INTO chat_messages (appointment_id, client_phone, sender, sender_name, text, created_at, is_read)
        VALUES (?, ?, 'master', 'Natali', ?, ?, 0)
        """, (app_id, app_row["client_phone"], f"📅 Майстер оновила час запису: {data.date} о {data.time} ({service_names}, {total_price:.0f} €)", now_iso))

    conn.commit()
    conn.close()
    return {"status": "ok"}

# --- Live Chat Endpoints (Between Master & Client) ---

@app.get("/api/chat/messages")
def get_chat_messages(appointment_id: Optional[int] = None, client_phone: Optional[str] = None, viewer: Optional[str] = "master"):
    conn = get_db()
    cursor = conn.cursor()
    safe_phone = sanitize_text(client_phone or "").strip()
    digits = re.sub(r'\D', '', safe_phone)
    suffix = digits[-9:] if len(digits) >= 9 else digits

    query = "SELECT * FROM chat_messages WHERE 1=1"
    params = []

    if appointment_id and suffix:
        query += " AND (appointment_id = ? OR client_phone LIKE ?)"
        params.extend([appointment_id, f"%{suffix}%"])
    elif appointment_id:
        query += " AND appointment_id = ?"
        params.append(appointment_id)
    elif suffix:
        query += " AND client_phone LIKE ?"
        params.append(f"%{suffix}%")

    query += " ORDER BY id ASC"
    cursor.execute(query, tuple(params))
    messages = [dict(r) for r in cursor.fetchall()]

    other_sender = 'client' if viewer == 'master' else 'master'
    if appointment_id:
        cursor.execute("UPDATE chat_messages SET is_read = 1 WHERE appointment_id = ? AND sender = ?", (appointment_id, other_sender))
    if suffix:
        cursor.execute("UPDATE chat_messages SET is_read = 1 WHERE client_phone LIKE ? AND sender = ?", (f"%{suffix}%", other_sender))

    conn.commit()
    conn.close()
    return {"status": "ok", "messages": messages}

@app.post("/api/chat/send")
def send_chat_message(data: SendChatMessageRequest):
    text = sanitize_text(data.text).strip()
    if not text:
        raise HTTPException(status_code=400, detail="Повідомлення не може бути порожнім")
    safe_phone = sanitize_text(data.client_phone).strip()
    sender = "client" if data.sender == "client" else "master"
    sender_name = sanitize_text(data.sender_name or ("Natali" if sender == "master" else "Клієнт"))

    conn = get_db()
    cursor = conn.cursor()
    now_iso = datetime.now().isoformat()
    cursor.execute("""
    INSERT INTO chat_messages (appointment_id, client_phone, sender, sender_name, text, created_at, is_read)
    VALUES (?, ?, ?, ?, ?, ?, 0)
    """, (data.appointment_id, safe_phone, sender, sender_name, text, now_iso))
    mid = cursor.lastrowid
    conn.commit()
    conn.close()
    return {
        "status": "ok",
        "message": {
            "id": mid,
            "appointment_id": data.appointment_id,
            "client_phone": safe_phone,
            "sender": sender,
            "sender_name": sender_name,
            "text": text,
            "created_at": now_iso,
            "is_read": 0
        }
    }

@app.get("/api/chat/unread-counts")
def get_unread_counts(viewer: Optional[str] = "master", phone: Optional[str] = None):
    conn = get_db()
    cursor = conn.cursor()
    target_sender = 'master' if viewer == 'client' else 'client'

    query = "SELECT appointment_id, client_phone, COUNT(*) as unread FROM chat_messages WHERE sender = ? AND is_read = 0"
    params = [target_sender]

    if phone:
        safe_phone = sanitize_text(phone).strip()
        digits = re.sub(r'\D', '', safe_phone)
        suffix = digits[-9:] if len(digits) >= 9 else digits
        if suffix:
            query += " AND client_phone LIKE ?"
            params.append(f"%{suffix}%")

    query += " GROUP BY appointment_id, client_phone"
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    total_unread = 0
    by_app = {}
    by_phone = {}
    for r in rows:
        unread = r["unread"]
        total_unread += unread
        if r["appointment_id"]:
            by_app[str(r["appointment_id"])] = unread
        if r["client_phone"]:
            by_phone[r["client_phone"]] = unread
    conn.close()
    return {"total_unread": total_unread, "by_app": by_app, "by_phone": by_phone}

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

@app.post("/api/finance/reset")
def reset_finance():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM transactions")
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "Касу успішно обнулено"}

# --- VIP Client Club & Loyalty Endpoints ---


class ClientProfileUpdate(BaseModel):
    current_phone: str
    name: str
    phone: str
    instagram: Optional[str] = ""
    telegram: Optional[str] = ""
    whatsapp: Optional[str] = ""
    facebook: Optional[str] = ""
    notes: Optional[str] = ""
    avatar_url: Optional[str] = ""

@app.post("/api/client/update-profile")
def update_client_profile(data: ClientProfileUpdate):
    conn = get_db()
    cursor = conn.cursor()
    safe_cur_phone = sanitize_text(data.current_phone).strip()
    digits = re.sub(r'\D', '', safe_cur_phone)
    suffix = digits[-9:] if len(digits) >= 9 else digits

    safe_name = sanitize_text(data.name).strip()
    safe_phone = sanitize_text(data.phone).strip()
    safe_insta = sanitize_text(data.instagram or '').strip()
    safe_tg = sanitize_text(data.telegram or '').strip()
    safe_wa = sanitize_text(data.whatsapp or '').strip()
    safe_fb = sanitize_text(data.facebook or '').strip()
    safe_notes = sanitize_text(data.notes or '').strip()
    safe_avatar = (data.avatar_url or '').strip()

    cursor.execute("SELECT id, avatar_url FROM clients WHERE phone = ? OR phone LIKE ?", (safe_cur_phone, f"%{suffix}%"))
    client = cursor.fetchone()
    if not client:
        # Create client if doesn't exist yet
        now_str = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO clients (name, phone, instagram, telegram, whatsapp, facebook, notes, avatar_url, created_at, points, is_vip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
        """, (safe_name, safe_phone, safe_insta, safe_tg, safe_wa, safe_fb, safe_notes, safe_avatar, now_str))
        conn.commit()
        new_id = cursor.lastrowid
        cursor.execute("SELECT * FROM clients WHERE id = ?", (new_id,))
        updated = cursor.fetchone()
        conn.close()
        return {"status": "ok", "client": dict(updated)}

    final_avatar = safe_avatar if safe_avatar else (client["avatar_url"] or "")

    cursor.execute("""
        UPDATE clients SET
            name = ?, phone = ?, instagram = ?, telegram = ?, whatsapp = ?, facebook = ?, notes = ?, avatar_url = ?
        WHERE id = ?
    """, (safe_name, safe_phone, safe_insta, safe_tg, safe_wa, safe_fb, safe_notes, final_avatar, client["id"]))
    conn.commit()

    cursor.execute("SELECT * FROM clients WHERE id = ?", (client["id"],))
    updated = cursor.fetchone()
    conn.close()
    return {"status": "ok", "client": dict(updated)}

@app.post("/api/client/avatar")
def update_client_avatar(data: ClientAvatarUpdate):
    conn = get_db()
    cursor = conn.cursor()
    phone_clean = sanitize_text(data.phone)
    cursor.execute("UPDATE clients SET avatar_url = ? WHERE phone = ? OR phone LIKE ?", (data.avatar_url, phone_clean, f"%{phone_clean[-9:]}%"))
    conn.commit()
    conn.close()
    return {"status": "ok", "avatar_url": data.avatar_url}

@app.post("/api/client/login-instagram")
def client_login_instagram(data: InstagramLoginRequest):
    conn = get_db()
    cursor = conn.cursor()
    raw = sanitize_text(data.instagram).strip()
    if not raw:
        conn.close()
        raise HTTPException(status_code=400, detail="Instagram handle required")
    
    clean_insta = raw.replace("https://instagram.com/", "").replace("https://www.instagram.com/", "").strip("/").lstrip("@").strip()
    if not clean_insta:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid Instagram handle")
    
    handle_with_at = f"@{clean_insta}"
    
    # Check if client exists by instagram handle
    cursor.execute("SELECT * FROM clients WHERE instagram = ? OR instagram = ? OR instagram LIKE ?", (handle_with_at, clean_insta, f"%{clean_insta}%"))
    client = cursor.fetchone()
    
    if not client:
        # Create new client with 50 points
        display_name = clean_insta.capitalize()
        cursor.execute("""
        INSERT INTO clients (name, phone, instagram, avatar_url, points, vip_tier, unlocked_emojis, created_at)
        VALUES (?, '', ?, '', 50, 'Gold VIP', '💅,✨,💖', ?)
        """, (display_name, handle_with_at, datetime.now().isoformat()))
        conn.commit()
        cursor.execute("SELECT * FROM clients WHERE id = ?", (cursor.lastrowid,))
        client = cursor.fetchone()
        
    completed_count = 0
    if client["phone"]:
        cursor.execute("SELECT COUNT(*) FROM appointments WHERE (client_phone = ? OR client_phone LIKE ?) AND status = 'completed'", (client["phone"], f"%{client['phone'][-9:]}%"))
        row = cursor.fetchone()
        if row:
            completed_count = row[0]
            
    conn.close()
    return {
        "status": "ok",
        "client": dict(client),
        "completed_count": completed_count
    }

@app.get("/api/client/profile-instagram")
def get_client_profile_instagram(instagram: str):
    conn = get_db()
    cursor = conn.cursor()
    raw = sanitize_text(instagram).strip()
    clean_insta = raw.replace("https://instagram.com/", "").replace("https://www.instagram.com/", "").strip("/").lstrip("@").strip()
    handle_with_at = f"@{clean_insta}"
    
    cursor.execute("SELECT * FROM clients WHERE instagram = ? OR instagram = ? OR instagram LIKE ?", (handle_with_at, clean_insta, f"%{clean_insta}%"))
    client = cursor.fetchone()
    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Client not found")
        
    appointments = []
    if client["phone"]:
        cursor.execute("SELECT * FROM appointments WHERE client_phone = ? OR client_phone LIKE ? ORDER BY date DESC, time DESC", (client["phone"], f"%{client['phone'][-9:]}%"))
        appointments = [dict(r) for r in cursor.fetchall()]
        
    conn.close()
    return {
        "client": dict(client),
        "appointments": appointments
    }

@app.post("/api/client/register")
def client_register(data: ClientRegisterRequest):
    conn = get_db()
    cursor = conn.cursor()
    
    name = sanitize_text(data.name).strip()
    phone = sanitize_text(data.phone).strip()
    pwd = data.password.strip()
    
    if not name or len(name) < 2:
        conn.close()
        raise HTTPException(status_code=400, detail="Будь ласка, вкажіть ваше ім'я")
        
    digits = re.sub(r'\D', '', phone)
    if len(digits) < 9:
        conn.close()
        raise HTTPException(status_code=400, detail="Введіть коректний номер телефону (мінімум 9 цифр)")
        
    if len(pwd) < 4:
        conn.close()
        raise HTTPException(status_code=400, detail="Пароль має містити щонайменше 4 символи")
        
    suffix = digits[-9:]
    cursor.execute("SELECT * FROM clients WHERE phone LIKE ? OR phone LIKE ?", (f"%{phone}%", f"%{suffix}%"))
    existing = cursor.fetchone()
    
    if existing:
        # If already exists and has a password
        if existing["password"]:
            conn.close()
            raise HTTPException(status_code=400, detail="Клієнт з таким номером уже зареєстрований! Будь ласка, оберіть «Увійти».")
        else:
            # Update legacy client with name and password
            cursor.execute("UPDATE clients SET name = ?, password = ? WHERE id = ?", (name, pwd, existing["id"]))
            conn.commit()
            client_data = dict(existing)
            client_data["name"] = name
            conn.close()
            return {"status": "ok", "message": "Реєстрація успішна!", "client": client_data}
            
    # New client registration
    now_str = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO clients (name, phone, password, created_at, points, is_vip)
        VALUES (?, ?, ?, ?, 0, 0)
    """, (name, phone, pwd, now_str))
    new_id = cursor.lastrowid
    conn.commit()
    
    cursor.execute("SELECT * FROM clients WHERE id = ?", (new_id,))
    new_client = dict(cursor.fetchone())
    conn.close()
    return {"status": "ok", "message": "Реєстрація успішна!", "client": new_client}

@app.post("/api/client/login-auth")
def client_login_auth(data: ClientPasswordLoginRequest):
    conn = get_db()
    cursor = conn.cursor()
    
    phone = sanitize_text(data.phone).strip()
    pwd = data.password.strip()
    
    digits = re.sub(r'\D', '', phone)
    if len(digits) < 9:
        conn.close()
        raise HTTPException(status_code=400, detail="Введіть коректний номер телефону")
        
    suffix = digits[-9:]
    cursor.execute("SELECT * FROM clients WHERE phone LIKE ? OR phone LIKE ?", (f"%{phone}%", f"%{suffix}%"))
    client = cursor.fetchone()
    
    if not client:
        # Check if they have existing appointments
        cursor.execute("SELECT client_name, client_phone FROM appointments WHERE client_phone LIKE ? ORDER BY id DESC LIMIT 1", (f"%{suffix}%",))
        app_row = cursor.fetchone()
        if app_row:
            # Create client account with this password
            now_str = datetime.now().isoformat()
            c_name = app_row["client_name"] or "Клієнтка"
            cursor.execute("""
                INSERT INTO clients (name, phone, password, created_at, points, is_vip)
                VALUES (?, ?, ?, ?, 0, 0)
            """, (c_name, phone, pwd, now_str))
            conn.commit()
            cursor.execute("SELECT * FROM clients WHERE phone = ?", (phone,))
            new_c = dict(cursor.fetchone())
            conn.close()
            return {"status": "ok", "client": new_c}
            
        conn.close()
        raise HTTPException(status_code=404, detail="Користувача з таким номером не знайдено. Будь ласка, зареєструйтесь.")
        
    stored_pwd = client["password"]
    if stored_pwd and stored_pwd != pwd:
        conn.close()
        raise HTTPException(status_code=401, detail="Невірний пароль! Спробуйте ще раз.")
        
    # If client didn't have password yet, set it now
    if not stored_pwd:
        cursor.execute("UPDATE clients SET password = ? WHERE id = ?", (pwd, client["id"]))
        conn.commit()
        
    client_dict = dict(client)
    conn.close()
    return {"status": "ok", "client": client_dict}

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
    safe_phone = sanitize_text(phone).strip()
    digits = re.sub(r'\D', '', safe_phone)
    suffix = digits[-9:] if len(digits) >= 9 else digits

    cursor.execute("SELECT * FROM clients WHERE phone = ? OR phone LIKE ?", (safe_phone, f"%{suffix}%"))
    client_row = cursor.fetchone()

    client_data = None
    if client_row:
        client_data = dict(client_row)
    else:
        # Fallback: check if client exists in previous appointments!
        cursor.execute("SELECT client_name, client_phone, client_notes FROM appointments WHERE client_phone LIKE ? ORDER BY id DESC LIMIT 1", (f"%{suffix}%",))
        app_row = cursor.fetchone()
        if app_row:
            client_data = {
                "id": 0,
                "name": app_row["client_name"] or "",
                "phone": app_row["client_phone"] or safe_phone,
                "instagram": "",
                "bonus_points": 0,
                "avatar_url": None,
                "is_vip": 0
            }
        else:
            client_data = {
                "id": 0,
                "name": "",
                "phone": safe_phone,
                "instagram": "",
                "bonus_points": 0,
                "avatar_url": None,
                "is_vip": 0
            }

    cursor.execute("SELECT * FROM appointments WHERE client_phone = ? OR client_phone LIKE ? ORDER BY date DESC, time DESC", (safe_phone, f"%{suffix}%"))
    appointments = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {
        "client": client_data,
        "appointments": appointments
    }

@app.get("/api/client/appointments")
def get_client_appointments(phone: str = Query("")):
    safe_phone = sanitize_text(phone).strip()
    if not safe_phone:
        return []
    digits = re.sub(r'\D', '', safe_phone)
    suffix = digits[-9:] if len(digits) >= 9 else digits
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, client_name, client_phone, service_names, date, time, end_time, total_price, status, payment_method, notes, created_at
    FROM appointments
    WHERE client_phone = ? OR client_phone LIKE ?
    ORDER BY date DESC, time DESC
    """, (safe_phone, f"%{suffix}%"))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/client/appointments/{app_id}/cancel")
def cancel_client_appointment(app_id: int, phone: str = Query("")):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, status, client_phone, client_name FROM appointments WHERE id = ?", (app_id,))
    app_row = cursor.fetchone()
    if not app_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    
    cursor.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ?", (app_id,))
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO chat_messages (appointment_id, client_phone, sender, sender_name, text, created_at, is_read)
    VALUES (?, ?, 'client', ?, 'Клієнт скасував цей запис через додаток.', ?, 0)
    """, (app_id, app_row["client_phone"], app_row["client_name"], now_str))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.post("/api/client/redeem")
def redeem_reward(data: RedeemRequest):
    conn = get_db()
    cursor = conn.cursor()
    safe_phone = sanitize_text(data.phone).strip()
    digits = re.sub(r'\D', '', safe_phone)
    suffix = digits[-9:] if len(digits) >= 9 else digits

    cursor.execute("SELECT id, points, unlocked_emojis, notes FROM clients WHERE phone = ? OR phone LIKE ?", (safe_phone, f"%{suffix}%"))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Клієнта не знайдено")

    # Look up reward details
    cursor.execute("SELECT * FROM vip_rewards WHERE id = ?", (data.item_id,))
    reward_row = cursor.fetchone()
    cost = data.points_cost if (data.points_cost and data.points_cost > 0) else (reward_row["cost"] if reward_row else 0)
    reward_icon = (reward_row["icon"] if reward_row else None) or data.reward_icon or "💎"
    reward_type = (reward_row["reward_type"] if reward_row else None) or "emoji"
    reward_title = (reward_row["title"] if reward_row else None) or data.reward_title or "Бонус"

    cur_points = row["points"] or 0
    if cur_points < cost:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Недостатньо балів. У вас {cur_points} 💎, а потрібно {cost} 💎")

    emojis = [e.strip() for e in (row["unlocked_emojis"] or "").split(",") if e.strip()]
    if reward_icon and reward_icon not in emojis and len(reward_icon) <= 4 and reward_icon != '🏷️':
        emojis.append(reward_icon)
    new_emojis_str = ",".join(emojis)

    existing_notes = row["notes"] or ""
    if 'знижк' in reward_title.lower() or reward_type == 'discount' or reward_icon == '🏷️':
        discount_entry = f"[💎 {reward_title}]"
        if discount_entry not in existing_notes:
            new_notes = f"{existing_notes} {discount_entry}".strip()
        else:
            new_notes = existing_notes
    else:
        new_notes = existing_notes

    new_points = cur_points - cost
    cursor.execute("UPDATE clients SET points = ?, unlocked_emojis = ?, notes = ? WHERE id = ?", (new_points, new_emojis_str, new_notes, row["id"]))
    conn.commit()
    conn.close()
    return {
        "status": "ok",
        "points": new_points,
        "unlocked_emojis": new_emojis_str,
        "reward_title": reward_title,
        "reward_icon": reward_icon
    }

@app.post("/api/client/appointments/{app_id}/pay")
def client_notify_payment(app_id: int, data: ClientPaymentNotifyRequest):
    conn = get_db()
    cursor = conn.cursor()
    method = sanitize_text(data.payment_method).strip().lower()
    cursor.execute("UPDATE appointments SET payment_method = ? WHERE id = ?", (method, app_id))

    now_iso = datetime.now().isoformat()
    method_names = {'bizum': 'Bizum', 'card_es': 'Картка ES (IBAN)', 'card_ua': 'Картка UA', 'paypal': 'PayPal', 'cash': 'Готівка'}
    m_label = method_names.get(method, method.upper())
    cursor.execute("SELECT client_name, client_phone FROM appointments WHERE id = ?", (app_id,))
    app_row = cursor.fetchone()
    c_name = (app_row["client_name"] if app_row else "Клієнтка")
    c_phone = (app_row["client_phone"] if app_row else "")

    cursor.execute("""
    INSERT INTO chat_messages (appointment_id, client_phone, sender, sender_name, text, created_at, is_read)
    VALUES (?, ?, 'client', ?, ?, ?, 0)
    """, (app_id, c_phone, c_name, f"💳 Оплата: обрано {m_label}. Дякую!", now_iso))

    conn.commit()
    conn.close()
    return {"status": "ok", "payment_method": method}


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

    cursor.execute("UPDATE clients SET points = COALESCE(points, 0) + 1 WHERE phone = ? OR phone LIKE ?", (safe_phone, f"%{safe_phone[-9:]}%"))
    conn.commit()
    conn.close()
    return {"status": "created"}

# --- Public Online Booking Endpoints ---

@app.get("/api/public/info")
def get_public_info():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT master_name, studio_name, phone, instagram, telegram, whatsapp, facebook, address, work_start, work_end, working_days, schedule_json, currency, about, bizum_phone, paypal_link, card_ua, card_es, accept_bizum, accept_card, accept_paypal, accept_cash, master_avatar FROM settings WHERE id = 1")
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
    cursor.execute("SELECT work_start, work_end, working_days, schedule_json, slot_step FROM settings WHERE id = 1")
    s = cursor.fetchone()
    if not s:
        conn.close()
        return []

    # Check if day is marked as working day (0=Sun, 1=Mon, ..., 6=Sat)
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        py_wd = dt.weekday()
        js_wd = (py_wd + 1) % 7
        
        day_schedule = None
        if s["schedule_json"]:
            try:
                sch_dict = json.loads(s["schedule_json"])
                day_schedule = sch_dict.get(str(js_wd))
            except Exception:
                day_schedule = None

        if day_schedule:
            if not day_schedule.get("active", True):
                conn.close()
                return []  # Day off / Non-working day!
            work_start_str = day_schedule.get("start") or s["work_start"] or "10:00"
            work_end_str = day_schedule.get("end") or s["work_end"] or "20:00"
        else:
            raw_wd = s["working_days"] if s["working_days"] else "1,2,3,4,5,6"
            active_days = [w.strip() for w in str(raw_wd).split(",") if w.strip()]
            if str(js_wd) not in active_days:
                conn.close()
                return []  # Day off / Non-working day!
            work_start_str = s["work_start"] or "10:00"
            work_end_str = s["work_end"] or "20:00"
    except Exception as e:
        work_start_str = s["work_start"] or "10:00"
        work_end_str = s["work_end"] or "20:00"

    work_start_m = time_to_minutes(work_start_str)
    work_end_m = time_to_minutes(work_end_str)
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

    # Validate that the selected day is an active working day and time is within work hours
    cursor.execute("SELECT work_start, work_end, working_days, schedule_json FROM settings WHERE id = 1")
    s = cursor.fetchone()
    if s:
        try:
            dt = datetime.strptime(data.date, "%Y-%m-%d")
            py_wd = dt.weekday()
            js_wd = (py_wd + 1) % 7
            day_schedule = None
            if s["schedule_json"]:
                try:
                    sch_dict = json.loads(s["schedule_json"])
                    day_schedule = sch_dict.get(str(js_wd))
                except Exception:
                    day_schedule = None

            if day_schedule:
                if not day_schedule.get("active", True):
                    conn.close()
                    raise HTTPException(status_code=400, detail="На жаль, цей день є вихідним у майстра. Будь ласка, оберіть робочий день.")
                day_start_m = time_to_minutes(day_schedule.get("start") or s["work_start"] or "10:00")
                day_end_m = time_to_minutes(day_schedule.get("end") or s["work_end"] or "20:00")
            else:
                raw_wd = s["working_days"] if s["working_days"] else "1,2,3,4,5,6"
                active_days = [w.strip() for w in str(raw_wd).split(",") if w.strip()]
                if str(js_wd) not in active_days:
                    conn.close()
                    raise HTTPException(status_code=400, detail="На жаль, цей день є вихідним у майстра. Будь ласка, оберіть робочий день.")
                day_start_m = time_to_minutes(s["work_start"] or "10:00")
                day_end_m = time_to_minutes(s["work_end"] or "20:00")

            if req_start < day_start_m or req_end > day_end_m:
                conn.close()
                raise HTTPException(status_code=400, detail="Обраний час виходить за межі робочого графіка майстра на цей день.")
        except HTTPException:
            raise
        except Exception:
            pass

    cursor.execute("SELECT time, end_time FROM appointments WHERE date = ? AND status != 'cancelled'", (data.date,))
    existing = cursor.fetchall()
    for b in existing:
        b_start = time_to_minutes(b["time"])
        b_end = time_to_minutes(b["end_time"])
        if not (req_end <= b_start or req_start >= b_end):
            conn.close()
            raise HTTPException(status_code=400, detail="На жаль, цей час вже зайняли. Будь ласка, оберіть інший час.")

    digits = re.sub(r'\D', '', safe_phone)
    suffix = digits[-9:] if len(digits) >= 9 else digits
    cursor.execute("SELECT id FROM clients WHERE phone = ? OR phone LIKE ?", (safe_phone, f"%{suffix}%"))
    client_row = cursor.fetchone()
    if client_row:
        client_id = client_row[0]
        cursor.execute("UPDATE clients SET name = ?, phone = ? WHERE id = ?", (safe_name, safe_phone, client_id))
    else:
        cursor.execute("INSERT INTO clients (name, phone, points, vip_tier, unlocked_emojis, created_at) VALUES (?, ?, 50, 'Gold VIP', '💅,✨,💖', ?)",
                       (safe_name, safe_phone, datetime.now().isoformat()))
        client_id = cursor.lastrowid

    now_iso = datetime.now().isoformat()
    cursor.execute("""
    INSERT INTO appointments (client_id, client_name, client_phone, service_names, date, time, end_time, total_price, status, payment_method, notes, source, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'cash', ?, 'client', ?)
    """, (client_id, safe_name, safe_phone, data.service_names, data.date, data.time, end_time, data.total_price, safe_notes, now_iso))
    aid = cursor.lastrowid

    # Create initial greeting/status message in chat
    cursor.execute("""
    INSERT INTO chat_messages (appointment_id, client_phone, sender, sender_name, text, created_at, is_read)
    VALUES (?, ?, 'master', 'Natali', ?, ?, 0)
    """, (aid, safe_phone, f"Привіт, {safe_name}! ✨ Ваше онлайн-бронювання на {data.date} о {data.time} ({data.service_names}) отримано та очікує підтвердження. Якщо треба скоригувати час або є запитання — пишіть тут!", now_iso))

    conn.commit()
    conn.close()

    return {"status": "success", "appointment_id": aid}

# --- Static frontend routing ---
@app.get("/")
def serve_index():
    return FileResponse("static/index.html")

@app.get("/book")
def serve_book():
    return FileResponse("static/book.html")

@app.get("/vip")
@app.get("/club")
@app.get("/client")
def serve_client_club():
    return FileResponse("static/client.html")


@app.get("/download/android")
@app.get("/download/android-apk")
def download_android():
    return FileResponse(
        "static/NataliNails_Android.apk",
        media_type="application/vnd.android.package-archive",
        filename="NataliNails_Android.apk"
    )

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
            <string>Natali Nails Web App</string>
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
    <string>Natali Nails</string>
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
    return Response(content=mobileconfig, media_type="application/octet-stream", headers={
        "Content-Disposition": 'attachment; filename="NataliNails.mobileconfig"',
        "Content-Type": "application/octet-stream"
    })

app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
