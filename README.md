# Dead Man's Switch

Emergency infrastructure shutdown system for physical security scenarios. Remote control of servers, switches, and hardware when physical access is compromised.

## Features

- **Remote Shutdown** - API or Telegram bot triggers coordinated infrastructure lockdown
- **2FA Required** - Static token + TOTP for all critical operations
- **Multi-Platform** - SSH (Linux/macOS/Windows), API endpoints, custom hardware via plugins
- **Encrypted Storage** - AES-256-GCM for credentials, PBKDF2 key derivation
- **Real-Time Monitoring** - 60s health checks on all configured hosts
- **Extensible** - Dynamic plugin loading from `plugins/` directory

## Threat Model

**Protects Against:**
- Physical facility breach (shutdown prevents hot data extraction)
- Equipment seizure or confiscation
- Credential theft from database (encrypted at rest)
- Unauthorized API access (token + TOTP required)

**Does Not Protect:**
- Compromised `MASTER_SECRET` (decrypts all data)
- Network interception (use HTTPS/VPN)
- Malicious plugins (full code execution)
- Running DMS instance with physical access
- Telegram metadata exposure

**OPSEC Warning - Telegram:**
- Bot metadata visible to Telegram servers (timing, user ID)
- Account linkable to phone number
- Message history may persist
- **For maximum security: use API-only mode, disable Telegram**

## Companion App

### WIP


## Quick Start

```bash
# Clone and setup
git clone <repository-url>
cd DeadManSwitch
mkdir -p data
cp .env.example .env

# Install dependencies
pip install -r requirements.txt

# First run - generates secrets
python main.py
```

**First run output:**
1. Static API token (for authentication)
2. TOTP QR code (scan with authenticator app)
3. SSH public key (deploy to target hosts)
4. Master encryption secret (add to `.env`)

Copy the `MASTER_SECRET` to your `.env` file, then restart:

```bash
# Edit .env with MASTER_SECRET
nano .env

# Start server
python main.py
```

### Configuration (`.env`)

```bash
DATA_DIR=./data
MASTER_SECRET=<from-first-run-output>
MONITORING_INTERVAL=60

# Optional - Telegram bot (reduces OPSEC)
TELEGRAM_BOT_TOKEN=<from @BotFather>
TELEGRAM_CHAT_ID=<your-chat-id>
```

### Docker

```bash
docker-compose up -d
docker-compose logs -f
```



## Usage

### Telegram Bot

**Login:** `/start` → Login → send token → send TOTP (valid 24h)

**Add SSH Host:**
1. Click "Add SSH Host"
2. Copy the displayed public key
3. On target host:
   ```bash
   # Add public key
   echo "<public-key>" >> ~/.ssh/authorized_keys
   
   # Configure passwordless shutdown
   echo "username ALL=(ALL) NOPASSWD: /sbin/shutdown" | sudo tee /etc/sudoers.d/dms-shutdown
   sudo chmod 440 /etc/sudoers.d/dms-shutdown
   ```
   
   **Note:** Systems without sudoers support should use root user for SSH access.

4. Send format: `ssh:hostname:username::description`
   - Example: `ssh:server.local:root::Production Server`
5. Confirm with TOTP after connection test

**Emergency Shutdown:** Button → TOTP → all hosts execute shutdown

### REST API

Docs: `http://localhost:8000/docs`

## Plugins

**Built-in:** SSH (Linux/macOS/Windows auto-detect), TrueNAS, vCenter, Proxmox

**Custom Plugin Example** (`plugins/power_switch.py`):

```python
class PowerSwitchPlugin:
    plugin_type = "power_switch"
    
    def test_connection(self, config):
        response = requests.get(f"http://{config['host']}/status")
        return {"status": "online" if response.ok else "offline"}
    
    def execute_shutdown(self, config):
        requests.post(f"http://{config['host']}/cutoff")
        return {"status": "executed"}
```

⚠️ **Plugins have full system access. Only use trusted code.**

Plugins auto-load from `plugins/` at startup.

Plugin ideas: 
 - IoT switches
 - Smart PDUs
 - Cloud APIs (AWS/GCP/Azure)
 - Custom hardware automation

## Monitoring

Continuous health checks every 60s (configurable). States: `online`, `offline`, `error`, `disabled`.

View: Telegram "System Status"



## Troubleshooting

**Bot not responding:**
- Check `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in `.env`
- View logs: `docker-compose logs -f`

**SSH failures:**
- Add public key to target `~/.ssh/authorized_keys`
- Test manually: `ssh user@host`

**TOTP errors:**
- Sync device clock (NTP)
- Check authenticator app time

## Security Notes

⚠️ **Destructive tool - understand implications before deployment.**

**Critical:**
- Never lose `MASTER_SECRET` (encrypted data unrecoverable)
- Store `data/` with strict access controls
- Use dedicated TOTP device
- Deploy DMS outside target infrastructure
- Test in non-production first
- Document offline recovery procedures

**Network:**
- Use HTTPS (reverse proxy with certs)
- Restrict API access (firewall/VPN)
- Consider Tor hidden service for maximum OPSEC
- Avoid public internet exposure

**Plugins:**
- Audit all code before deployment
- Plugins execute with full privileges
- Malicious code compromises entire infrastructure

## License

MIT License - see LICENSE file
