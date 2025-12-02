import sqlite3
import secrets
import os
from datetime import datetime
from pathlib import Path
import encryption

# Use data directory for persistence in Docker
DATA_DIR = os.getenv("DATA_DIR", "./data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_FILE = os.path.join(DATA_DIR, "dms.db")


def get_connection():
    """Get database connection."""
    return sqlite3.connect(DB_FILE)


def init_db():
    """Initialize the database with required tables."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Create logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            source TEXT DEFAULT 'API',
            status TEXT
        )
    """)
    
    # Create config table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Create SSH hosts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ssh_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            user TEXT NOT NULL,
            command TEXT DEFAULT 'shutdown -h now',
            description TEXT,
            enabled INTEGER DEFAULT 1,
            last_check TEXT,
            last_status TEXT DEFAULT 'unknown',
            last_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(host, user)
        )
    """)
    
    # Create API hosts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL UNIQUE,
            api_type TEXT NOT NULL,
            api_key TEXT,
            api_endpoint TEXT,
            description TEXT,
            enabled INTEGER DEFAULT 1,
            last_check TEXT,
            last_status TEXT DEFAULT 'unknown',
            last_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telegram_sessions (
            user_id INTEGER PRIMARY KEY,
            authenticated_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()


def log_action(action: str, details: str = "", source: str = "API", status: str = "info"):
    """Log an action to the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        
        cursor.execute("""
            INSERT INTO logs (timestamp, action, details, source, status)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, action, details, source, status))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Failed to log action: {e}")
        return False


def get_config(key: str) -> str | None:
    """Retrieve a configuration value from the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None
    except Exception as e:
        print(f"Failed to get config: {e}")
        return None


def set_config(key: str, value: str):
    """Set a configuration value in the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        
        cursor.execute("""
            INSERT INTO config (key, value, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
        """, (key, value, timestamp, timestamp))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Failed to set config: {e}")
        return False


def get_all_logs(limit: int = 100):
    """Retrieve recent logs from the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, action, details, source, status
            FROM logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                "timestamp": row[0],
                "action": row[1],
                "details": row[2],
                "source": row[3],
                "status": row[4]
            }
            for row in results
        ]
    except Exception as e:
        print(f"Failed to retrieve logs: {e}")
        return []


# ==============================
# SSH HOSTS MANAGEMENT
# ==============================

def add_ssh_host(host: str, user: str, description: str = ""):
    """Add a new SSH host to the database with encrypted sensitive fields."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        
        # Encrypt sensitive fields
        encrypted_user = encryption.encrypt(user) if encryption.is_initialized() else user
        # Command is no longer used, always empty (auto-detected at runtime)
        encrypted_command = encryption.encrypt("") if encryption.is_initialized() else ""
        
        cursor.execute("""
            INSERT INTO ssh_hosts (host, user, command, description, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(host, user) DO UPDATE SET
                command = excluded.command,
                description = excluded.description,
                updated_at = excluded.updated_at
        """, (host, encrypted_user, encrypted_command, description, timestamp, timestamp))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Failed to add SSH host: {e}")
        return False


def get_all_ssh_hosts(enabled_only: bool = True):
    """Retrieve all SSH hosts from the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        if enabled_only:
            cursor.execute("""
                SELECT id, host, user, command, description, enabled, 
                       last_check, last_status, last_error, created_at, updated_at
                FROM ssh_hosts
                WHERE enabled = 1
                ORDER BY id
            """)
        else:
            cursor.execute("""
                SELECT id, host, user, command, description, enabled,
                       last_check, last_status, last_error, created_at, updated_at
                FROM ssh_hosts
                ORDER BY id
            """)
        
        results = cursor.fetchall()
        conn.close()
        
        # Decrypt sensitive fields
        decrypted_results = []
        for row in results:
            try:
                decrypted_user = encryption.decrypt(row[2]) if encryption.is_initialized() else row[2]
                # Command field is deprecated (always empty), but still in DB for backward compatibility
                decrypted_command = ""
                try:
                    if row[3] and encryption.is_initialized():
                        decrypted_command = encryption.decrypt(row[3])
                except:
                    decrypted_command = ""
            except Exception as e:
                # Fallback to raw value if decryption fails (backward compatibility)
                print(f"Decryption failed for host {row[1]}: {e}")
                decrypted_user = row[2]
                decrypted_command = ""
            
            decrypted_results.append({
                "id": row[0],
                "host": row[1],
                "user": decrypted_user,
                "command": decrypted_command,
                "description": row[4],
                "enabled": bool(row[5]),
                "last_check": row[6],
                "last_status": row[7],
                "last_error": row[8],
                "created_at": row[9],
                "updated_at": row[10]
            })
        
        return decrypted_results
    except Exception as e:
        print(f"Failed to retrieve SSH hosts: {e}")
        return []


def delete_ssh_host(host: str, user: str):
    """Delete an SSH host from the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM ssh_hosts WHERE host = ? AND user = ?", (host, user))
        
        conn.commit()
        deleted = cursor.rowcount > 0
        conn.close()
        return deleted
    except Exception as e:
        print(f"Failed to delete SSH host: {e}")
        return False


def toggle_ssh_host(host: str, user: str, enabled: bool):
    """Enable/disable an SSH host."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        
        cursor.execute("""
            UPDATE ssh_hosts
            SET enabled = ?, updated_at = ?
            WHERE host = ? AND user = ?
        """, (1 if enabled else 0, timestamp, host, user))
        
        conn.commit()
        updated = cursor.rowcount > 0
        conn.close()
        return updated
    except Exception as e:
        print(f"Failed to toggle SSH host: {e}")
        return False


def update_ssh_host_status(host: str, user: str, status: str, error: str = ""):
    """Update the last check status of an SSH host."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        # WARNING: 'user' column is encrypted (non-deterministic). Matching by plaintext will fail.
        # Fallback: update by host only when a single row matches; otherwise skip.
        cursor.execute("SELECT id, user FROM ssh_hosts WHERE host = ?", (host,))
        rows = cursor.fetchall()
        target_id = None
        if len(rows) == 1:
            target_id = rows[0][0]
        else:
            # Try to decrypt and match provided user
            try:
                for r in rows:
                    encrypted_user = r[1]
                    from encryption import decrypt, is_initialized
                    plain = decrypt(encrypted_user) if is_initialized() else encrypted_user
                    if plain == user:
                        target_id = r[0]
                        break
            except Exception:
                pass
        if target_id is not None:
            cursor.execute("""
                UPDATE ssh_hosts
                SET last_check = ?, last_status = ?, last_error = ?, updated_at = ?
                WHERE id = ?
            """, (timestamp, status, error, timestamp, target_id))
        else:
            # Unable to resolve row; log minimal diagnostic
            print(f"Failed to resolve SSH host for status update: host={host} user={user}")
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Failed to update SSH host status: {e}")
        return False


# ==============================
# API HOSTS MANAGEMENT
# ==============================

def add_api_host(host: str, api_type: str, api_key: str = "", api_endpoint: str = "", description: str = ""):
    """Add a new API host to the database with encrypted API key."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        
        # Encrypt API key
        encrypted_api_key = encryption.encrypt(api_key) if encryption.is_initialized() and api_key else api_key
        
        cursor.execute("""
            INSERT INTO api_hosts (host, api_type, api_key, api_endpoint, description, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                api_type = excluded.api_type,
                api_key = excluded.api_key,
                api_endpoint = excluded.api_endpoint,
                description = excluded.description,
                updated_at = excluded.updated_at
        """, (host, api_type, encrypted_api_key, api_endpoint, description, timestamp, timestamp))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Failed to add API host: {e}")
        return False


def get_all_api_hosts(enabled_only: bool = True):
    """Retrieve all API hosts from the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        if enabled_only:
            cursor.execute("""
                SELECT id, host, api_type, api_key, api_endpoint, description, enabled,
                       last_check, last_status, last_error, created_at, updated_at
                FROM api_hosts
                WHERE enabled = 1
                ORDER BY id
            """)
        else:
            cursor.execute("""
                SELECT id, host, api_type, api_key, api_endpoint, description, enabled,
                       last_check, last_status, last_error, created_at, updated_at
                FROM api_hosts
                ORDER BY id
            """)
        
        results = cursor.fetchall()
        conn.close()
        
        # Decrypt API keys
        decrypted_results = []
        for row in results:
            try:
                decrypted_api_key = encryption.decrypt(row[3]) if encryption.is_initialized() and row[3] else row[3]
            except:
                # Fallback to raw value if decryption fails (backward compatibility)
                decrypted_api_key = row[3]
            
            decrypted_results.append({
                "id": row[0],
                "host": row[1],
                "api_type": row[2],
                "api_key": decrypted_api_key,
                "api_endpoint": row[4],
                "description": row[5],
                "enabled": bool(row[6]),
                "last_check": row[7],
                "last_status": row[8],
                "last_error": row[9],
                "created_at": row[10],
                "updated_at": row[11]
            })
        
        return decrypted_results
    except Exception as e:
        print(f"Failed to retrieve API hosts: {e}")
        return []


def delete_api_host(host: str):
    """Delete an API host from the database."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM api_hosts WHERE host = ?", (host,))
        
        conn.commit()
        deleted = cursor.rowcount > 0
        conn.close()
        return deleted
    except Exception as e:
        print(f"Failed to delete API host: {e}")
        return False


def toggle_api_host(host: str, enabled: bool):
    """Enable/disable an API host."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        
        cursor.execute("""
            UPDATE api_hosts
            SET enabled = ?, updated_at = ?
            WHERE host = ?
        """, (1 if enabled else 0, timestamp, host))
        
        conn.commit()
        updated = cursor.rowcount > 0
        conn.close()
        return updated
    except Exception as e:
        print(f"Failed to toggle API host: {e}")
        return False


def update_api_host_status(host: str, status: str, error: str = ""):
    """Update the last check status of an API host."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        
        cursor.execute("""
            UPDATE api_hosts
            SET last_check = ?, last_status = ?, last_error = ?, updated_at = ?
            WHERE host = ?
        """, (timestamp, status, error, timestamp, host))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Failed to update API host status: {e}")
        return False


def track_session(ip_address: str, user_agent: str = "", endpoint: str = "", action: str = ""):
    """Track API session and detect new IPs."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE ip_address = ?", (ip_address,))
        is_new = cursor.fetchone()[0] == 0
        
        timestamp = datetime.utcnow().isoformat()
        
        cursor.execute("""
            INSERT INTO sessions (ip_address, user_agent, endpoint, action, timestamp, is_new_ip)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip_address, user_agent, endpoint, action, timestamp, 1 if is_new else 0))
        
        conn.commit()
        conn.close()
        return is_new
    except Exception as e:
        print(f"Failed to track session: {e}")
        return False


def get_recent_sessions(limit: int = 50):
    """Get recent session records."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT ip_address, user_agent, endpoint, action, timestamp, is_new_ip
            FROM sessions
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                "ip": row[0],
                "user_agent": row[1],
                "endpoint": row[2],
                "action": row[3],
                "timestamp": row[4],
                "new_ip": bool(row[5])
            }
            for row in results
        ]
    except Exception as e:
        print(f"Failed to get sessions: {e}")
        return []


def add_telegram_session(user_id: int) -> bool:
    from datetime import datetime, timedelta
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow()
    expires = now + timedelta(hours=24)
    try:
        cursor.execute(
            "INSERT OR REPLACE INTO telegram_sessions (user_id, authenticated_at, expires_at) VALUES (?, ?, ?)",
            (user_id, now.isoformat(), expires.isoformat())
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def is_telegram_session_valid(user_id: int) -> bool:
    from datetime import datetime
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT expires_at FROM telegram_sessions WHERE user_id = ?",
        (user_id,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
    
    expires = datetime.fromisoformat(result[0])
    return datetime.utcnow() < expires


def remove_telegram_session(user_id: int) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM telegram_sessions WHERE user_id = ?", (user_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def cleanup_expired_telegram_sessions() -> int:
    from datetime import datetime
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    cursor.execute("DELETE FROM telegram_sessions WHERE expires_at < ?", (now,))
    conn.commit()
    count = cursor.rowcount
    conn.close()
    return count

