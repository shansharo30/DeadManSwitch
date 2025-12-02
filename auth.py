import secrets
import pyotp
import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from database import get_config, set_config, log_action
import encryption
import os

SECRET_TOKEN_KEY = "SECRET_TOKEN"
TOTP_SECRET_KEY = "TOTP_SECRET"
SSH_PRIVATE_KEY = "SSH_PRIVATE_KEY"
SSH_PUBLIC_KEY = "SSH_PUBLIC_KEY"
ENCRYPTION_SALT_KEY = "ENCRYPTION_SALT"


class SetupRequired(Exception):
    """Raised when initial setup requires the user to add settings and restart."""
    pass


def preflight_check() -> bool:
    """Ensure encryption salt and MASTER_SECRET are ready before server start.
    Returns True when ready to start, False when user action is required.
    """
    import base64
    salt_b64 = get_config(ENCRYPTION_SALT_KEY)
    if not salt_b64:
        # First run: if MASTER_SECRET provided, proceed automatically; otherwise, generate and exit
        env_secret = os.getenv("MASTER_SECRET", "")
        if env_secret:
            salt = encryption.initialize_encryption(env_secret, None)
            set_config(ENCRYPTION_SALT_KEY, base64.b64encode(salt).decode())
            return True
        # No secret provided: generate one, show to user, and exit
        generated = secrets.token_urlsafe(32)
        salt = encryption.initialize_encryption(generated, None)
        set_config(ENCRYPTION_SALT_KEY, base64.b64encode(salt).decode())
        print(f"\n{'='*60}")
        print("Master Secret (add to .env as MASTER_SECRET):")
        print(generated)
        print(f"{'='*60}\n")
        print(f"{'='*60}")
        print("First-time setup: add the Master Secret to .env and restart.")
        print("\nNext steps:\n1) Copy the Master Secret above\n2) Add to .env as: MASTER_SECRET=<that value>\n3) Save and restart")
        print(f"{'='*60}\n")
        return False
    # Salt exists; require MASTER_SECRET in environment
    salt = base64.b64decode(salt_b64)
    master_secret = os.getenv("MASTER_SECRET", "")
    if not master_secret:
        print(f"\n{'='*60}")
        print("MASTER_SECRET not set in environment.")
        print("Add the Master Secret printed on first run to .env and restart.")
        print(f"{'='*60}\n")
        return False
    # Ready: initialize encryption and proceed
    encryption.initialize_encryption(master_secret, salt)
    return True


def setup_secrets():
    """Initialize authentication secrets. Returns (static_token, totp_secret).
    If setup isn't complete (no salt or MASTER_SECRET), prints instructions and returns ("", "").
    """
    import base64
    # Ensure encryption is initialized only when salt and master secret are present
    salt_b64 = get_config(ENCRYPTION_SALT_KEY)
    if not salt_b64:
        # If no salt, only proceed when MASTER_SECRET is provided via env
        env_secret = os.getenv("MASTER_SECRET", "")
        if not env_secret:
            print(f"\n{'='*60}")
            print("Setup incomplete: MASTER_SECRET not configured.")
            print("Add MASTER_SECRET to your .env and restart.")
            print(f"{'='*60}\n")
            return "", ""
        salt = encryption.initialize_encryption(env_secret, None)
        set_config(ENCRYPTION_SALT_KEY, base64.b64encode(salt).decode())
    else:
        salt = base64.b64decode(salt_b64)
    
    master_secret = os.getenv("MASTER_SECRET", "")
    if not master_secret:
        print(f"\n{'='*60}")
        print("MASTER_SECRET not set in environment.")
        print("Add the Master Secret printed on first run to .env and restart.")
        print(f"{'='*60}\n")
        return "", ""
    encryption.initialize_encryption(master_secret, salt)
    
    static_token = get_config(SECRET_TOKEN_KEY)
    if not static_token:
        static_token = secrets.token_urlsafe(32)
        set_config(SECRET_TOKEN_KEY, static_token)
        log_action("secret_generated", "Static token created", "SYSTEM", "info")
        print(f"\n{'='*60}")
        print(f"Static Token (save securely):")
        print(f"{static_token}")
        print(f"{'='*60}\n")
    
    totp_secret = get_config(TOTP_SECRET_KEY)
    if not totp_secret:
        totp_secret = pyotp.random_base32()
        set_config(TOTP_SECRET_KEY, totp_secret)
        
        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(name="DMS-API", issuer_name="DeadManSwitch")
        
        log_action("totp_generated", "TOTP secret created", "SYSTEM", "info")
        print(f"\nTOTP Secret: {totp_secret}")
        print(f"Scan QR code with authenticator app:\n")
        
        qr = qrcode.QRCode()
        qr.add_data(provisioning_uri)
        qr.make()
        qr.print_ascii(invert=True)
        
        print(f"\nIssuer: DeadManSwitch | Account: DMS-API\n")
    
    private_key_pem = get_config(SSH_PRIVATE_KEY)
    public_key_pem = get_config(SSH_PUBLIC_KEY)
    
    if not private_key_pem or not public_key_pem:
        print(f"\nGenerating SSH keypair...")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        set_config(SSH_PRIVATE_KEY, private_key_pem)
        set_config(SSH_PUBLIC_KEY, public_key_pem)
        
        log_action("ssh_key_generated", "SSH keypair created", "SYSTEM", "info")
        
        print(f"SSH Public Key (add to target ~/.ssh/authorized_keys):")
        print(f"\n{public_key_pem}\n")
    
    return static_token, totp_secret


def get_static_token() -> str:
    return get_config(SECRET_TOKEN_KEY)


def get_totp_secret() -> str:
    return get_config(TOTP_SECRET_KEY)


def verify_totp(code: str) -> bool:
    try:
        totp_secret = get_totp_secret()
        if not totp_secret:
            return False
        
        totp = pyotp.TOTP(totp_secret)
        is_valid = totp.verify(code, valid_window=1)
        
        if not is_valid:
            log_action("auth_failed", "Invalid TOTP", "AUTH", "warning")
        
        return is_valid
    except Exception:
        return False


def verify_static_token_value(token: str) -> bool:
    try:
        expected_token = get_static_token()
        if not expected_token:
            return False
        
        is_valid = secrets.compare_digest(token, expected_token)
        
        if not is_valid:
            log_action("auth_failed", "Invalid token", "AUTH", "warning")
        
        return is_valid
    except Exception:
        return False


def get_ssh_private_key() -> str:
    return get_config(SSH_PRIVATE_KEY)


def get_ssh_public_key() -> str:
    return get_config(SSH_PUBLIC_KEY)
