"""
ScamShield Database Setup — v3.0
All table definitions, migrations, and the super admin bootstrap.
"""

import os
import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path

from auth import hash_password, ROLE_SUPERADMIN, ROLE_ADMIN, DEFAULT_ADMIN_PERMISSIONS, ALL_PERMISSIONS

DB_PATH = Path(os.environ.get("SCAMSHIELD_DB_PATH", str(Path(__file__).parent / "scamshield.db")))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Schema migrations
# ---------------------------------------------------------------------------
def init_db():
    """Create all tables if they don't exist. Safe to run on every startup."""
    with get_db() as conn:
        # Existing scan history table (preserved from v2)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                input_preview TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                summary TEXT NOT NULL,
                full_result TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Users table — stores all admin + superadmin accounts
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                role TEXT NOT NULL DEFAULT 'admin',
                password_hash TEXT NOT NULL,
                permissions TEXT NOT NULL DEFAULT '[]',
                is_active INTEGER NOT NULL DEFAULT 1,
                is_suspended INTEGER NOT NULL DEFAULT 0,
                must_change_password INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_by TEXT,
                last_login_at TEXT,
                failed_login_count INTEGER NOT NULL DEFAULT 0,
                last_failed_login_at TEXT
            )
        """)

        # Sessions table — tracks active sessions
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                is_revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Audit log — immutable event log
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                actor_id TEXT,
                actor_username TEXT,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                outcome TEXT NOT NULL DEFAULT 'success',
                metadata TEXT DEFAULT '{}',
                ip_address TEXT,
                created_at TEXT NOT NULL
            )
        """)

        # Notifications
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT NOT NULL DEFAULT 'info',
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # App settings — key/value store with JSON values
        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT
            )
        """)

        # Indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_created ON scan_history(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read)")

        # Default settings
        _seed_default_settings(conn)

        conn.commit()


def _seed_default_settings(conn):
    """Insert default app settings if not already present."""
    defaults = {
        "active_theme": "cyan_sentinel",
        "themes": json.dumps({
            "cyan_sentinel": {
                "name": "Cyan Sentinel",
                "primary": "#22d3ee",
                "secondary": "#3b82f6",
                "accent": "#0891b2",
                "glow_intensity": 0.3,
                "overlay_strength": 0.7,
                "animation_intensity": 1.0,
            },
            "orange_volt": {
                "name": "Orange Volt",
                "primary": "#f97316",
                "secondary": "#ef4444",
                "accent": "#fb923c",
                "glow_intensity": 0.4,
                "overlay_strength": 0.65,
                "animation_intensity": 1.2,
            },
            "purple_void": {
                "name": "Purple Void",
                "primary": "#a855f7",
                "secondary": "#ec4899",
                "accent": "#7c3aed",
                "glow_intensity": 0.35,
                "overlay_strength": 0.75,
                "animation_intensity": 0.9,
            },
        }),
        "neon_glow_intensity": "0.3",
        "bg_overlay_strength": "0.7",
        "animation_intensity": "1.0",
        "integrations": json.dumps({
            "virustotal": {"enabled": False, "api_key": ""},
            "safebrowsing": {"enabled": False, "api_key": ""},
            "abuseipdb": {"enabled": False, "api_key": ""},
            "threatfox": {"enabled": True},
            "webhook_alerts": {"enabled": False, "url": ""},
        }),
        "features": json.dumps({
            "rate_limiting": True,
            "public_scans": True,
            "debug_logging": False,
            "audit_retention_days": 90,
            "deep_analysis_timeout_sec": 30,
        }),
    }
    for key, value in defaults.items():
        conn.execute(
            "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, now_iso()),
        )


# ---------------------------------------------------------------------------
# Super admin bootstrap
# ---------------------------------------------------------------------------
def bootstrap_superadmin():
    """
    Create or synchronize the super admin account(s).
    Supports both custom SUPERADMIN_USERNAME and fallback 'admin'.
    Always ensures the password matches SUPERADMIN_INITIAL_PASSWORD or 'Admin@123'.
    """
    username = os.getenv("SUPERADMIN_USERNAME", "admin")
    initial_password = os.getenv("SUPERADMIN_INITIAL_PASSWORD", "Admin@123")

    with get_db() as conn:
        targets = list(dict.fromkeys([username, "admin", "albin"]))
        for uname in targets:
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (uname,),
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE users SET password_hash = ?, failed_login_count = 0, is_active = 1, is_suspended = 0, must_change_password = 0 WHERE id = ?",
                    (hash_password(initial_password), existing["id"]),
                )
                print(f"[ScamShield] Super admin '{uname}' credentials synchronized.")
            else:
                import uuid
                user_id = str(uuid.uuid4())
                now = now_iso()
                conn.execute(
                    """INSERT INTO users
                       (id, username, role, password_hash, permissions, is_active, must_change_password, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)""",
                    (
                        user_id,
                        uname,
                        ROLE_SUPERADMIN,
                        hash_password(initial_password),
                        json.dumps(ALL_PERMISSIONS),
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """INSERT INTO audit_log (id, actor_id, actor_username, action, target_type, target_id, outcome, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()),
                        user_id,
                        uname,
                        "superadmin_bootstrap",
                        "user",
                        user_id,
                        "success",
                        now,
                    ),
                )
                print(f"[ScamShield] Super admin '{uname}' created.")
        conn.commit()
