from fastapi import FastAPI, Request, Header, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from contextlib import asynccontextmanager
import logging
import uvicorn
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from database import (
    init_db, log_action, get_all_logs,
    add_ssh_host, get_all_ssh_hosts, delete_ssh_host, toggle_ssh_host,
    add_api_host, get_all_api_hosts, delete_api_host, toggle_api_host,
    track_session, get_recent_sessions
)
from auth import setup_secrets, verify_static_token_value, verify_totp, get_ssh_public_key
from dms_logic import (
    test_ssh_connection, test_api_connection,
    start_monitoring, stop_monitoring,
    initiate_hard_poweroff, get_shutdown_status, is_shutdown_in_progress
)
from telegram_bot import notify_new_ip, notify_shutdown, notify_host_added, notify_host_removed, start_bot
from plugins import list_plugins

logger = logging.getLogger(__name__)


def print_banner():
    """Print startup banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║              DEAD MAN'S SWITCH - EMERGENCY SHUTDOWN          ║
    ║                                                              ║
    ║  Physical OPSEC • Remote Infrastructure Control • Fail-Safe  ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print_banner()
    logger.info("Starting Dead Man's Switch API")
    
    init_db()
    # Ensure configuration is ready even when running via `uvicorn main:app`
    from auth import preflight_check
    ready = preflight_check()
    started = False
    if ready:
        static_token, totp_secret = setup_secrets()
        log_action("startup", "API initialized", "SYSTEM", "info")
        start_monitoring()
        start_bot()
        started = True
    else:
        logger.warning("Setup required: configure MASTER_SECRET in .env and restart.")
        log_action("setup_required", "Waiting for MASTER_SECRET", "SYSTEM", "warning")
    
    yield
    
    if started:
        stop_monitoring()
        log_action("shutdown", "API stopped", "SYSTEM", "info")
        logger.info("Shutdown complete")


app = FastAPI(
    title="Dead Man's Switch API",
    description="Infrastructure management and emergency shutdown system",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs"
)


class TOTPRequest(BaseModel):
    code: str


class SSHHostRequest(BaseModel):
    host: str
    user: str
    description: str = ""


class APIHostRequest(BaseModel):
    host: str
    api_type: str
    api_key: str
    api_endpoint: str = ""
    description: str = ""


async def verify_static_token(x_auth_token: Optional[str] = Header(None)):
    if not x_auth_token:
        log_action("auth_failed", "Missing auth token", "API", "warning")
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if not verify_static_token_value(x_auth_token):
        log_action("auth_failed", "Invalid token", "API", "error")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return True


async def track_request(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    endpoint = request.url.path
    
    is_new = track_session(client_ip, user_agent, endpoint, request.method)
    
    if is_new:
        notify_new_ip(client_ip, endpoint)
        log_action("new_ip_detected", f"IP: {client_ip}, Endpoint: {endpoint}", "SECURITY", "warning")


@app.get("/")
async def health_check():
    return {"status": "operational", "version": "2.0.0"}


@app.get("/plugins")
async def get_available_plugins(authenticated: bool = Depends(verify_static_token)):
    """List available target plugins."""
    plugins = list_plugins()
    return {
        "status": "ok",
        "plugins": plugins
    }


@app.get("/keys")
async def get_public_key(authenticated: bool = Depends(verify_static_token)):
    """Retrieve SSH public key."""
    public_key = get_ssh_public_key()
    return {
        "status": "ok",
        "public_key": public_key
    }


@app.get("/hosts/ssh")
async def list_ssh_hosts(
    request: Request,
    authenticated: bool = Depends(verify_static_token)
):
    """List all SSH hosts."""
    await track_request(request)
    
    hosts = get_all_ssh_hosts(enabled_only=False)
    return {
        "status": "ok",
        "count": len(hosts),
        "hosts": hosts
    }


@app.post("/hosts/ssh")
async def add_ssh_host_endpoint(
    request: Request,
    data: SSHHostRequest,
    authenticated: bool = Depends(verify_static_token)
):
    """Add new SSH host with connection test."""
    await track_request(request)
    
    test = test_ssh_connection(data.host, data.user)
    
    if not test["success"]:
        return JSONResponse(
            status_code=400,
            content={
                "status": "test_failed",
                "message": "Connection test failed",
                "details": test
            }
        )
    
    if add_ssh_host(data.host, data.user, data.description):
        notify_host_added(f"{data.user}@{data.host}", "ssh")
        log_action("host_added", f"SSH: {data.user}@{data.host}", "API", "info")
        return {
            "status": "added",
            "message": "Host added successfully",
            "test": test
        }
    
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Failed to add host"}
    )


@app.delete("/hosts/ssh/{host}/{user}")
async def remove_ssh_host_endpoint(
    request: Request,
    host: str,
    user: str,
    totp: TOTPRequest,
    authenticated: bool = Depends(verify_static_token)
):
    """Remove SSH host (requires TOTP)."""
    await track_request(request)
    
    if not verify_totp(totp.code):
        log_action("totp_failed", f"Failed TOTP for SSH host removal: {user}@{host}", "API", "warning")
        raise HTTPException(status_code=401, detail="Invalid TOTP code")
    
    if delete_ssh_host(host, user):
        notify_host_removed(f"{user}@{host}")
        log_action("host_removed", f"SSH: {user}@{host}", "API", "warning")
        return {"status": "removed"}
    
    return JSONResponse(
        status_code=404,
        content={"status": "not_found"}
    )


@app.patch("/hosts/ssh/{host}/{user}")
async def toggle_ssh_host_endpoint(
    request: Request,
    host: str,
    user: str,
    totp: TOTPRequest,
    authenticated: bool = Depends(verify_static_token)
):
    """Enable/disable SSH host (requires TOTP)."""
    await track_request(request)
    
    if not verify_totp(totp.code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")
    
    hosts = get_all_ssh_hosts(enabled_only=False)
    current_host = next((h for h in hosts if h["host"] == host and h["user"] == user), None)
    
    if not current_host:
        return JSONResponse(status_code=404, content={"status": "not_found"})
    
    new_state = not current_host["enabled"]
    
    if toggle_ssh_host(host, user, new_state):
        log_action("host_toggled", f"SSH: {user}@{host} -> {'enabled' if new_state else 'disabled'}", "API", "info")
        return {"status": "updated", "enabled": new_state}
    
    return JSONResponse(status_code=500, content={"status": "error"})


@app.get("/hosts/api")
async def list_api_hosts(
    request: Request,
    authenticated: bool = Depends(verify_static_token)
):
    """List all API hosts."""
    await track_request(request)
    
    hosts = get_all_api_hosts(enabled_only=False)
    return {
        "status": "ok",
        "count": len(hosts),
        "hosts": hosts
    }


@app.post("/hosts/api")
async def add_api_host_endpoint(
    request: Request,
    data: APIHostRequest,
    authenticated: bool = Depends(verify_static_token)
):
    """Add new API host with connection test."""
    await track_request(request)
    
    plugins = list_plugins()
    if data.api_type not in plugins:
        return JSONResponse(
            status_code=400,
            content={
                "status": "invalid_type",
                "message": f"Unsupported type: {data.api_type}",
                "available": plugins
            }
        )
    
    test = test_api_connection(data.host, data.api_type, data.api_key, data.api_endpoint)
    
    if not test["success"]:
        return JSONResponse(
            status_code=400,
            content={
                "status": "test_failed",
                "message": "Connection test failed",
                "details": test
            }
        )
    
    if add_api_host(data.host, data.api_type, data.api_key, data.api_endpoint, data.description):
        notify_host_added(data.host, data.api_type)
        log_action("host_added", f"{data.api_type}: {data.host}", "API", "info")
        return {
            "status": "added",
            "message": "Host added successfully",
            "test": test
        }
    
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Failed to add host"}
    )


@app.delete("/hosts/api/{host}")
async def remove_api_host_endpoint(
    request: Request,
    host: str,
    totp: TOTPRequest,
    authenticated: bool = Depends(verify_static_token)
):
    """Remove API host (requires TOTP)."""
    await track_request(request)
    
    if not verify_totp(totp.code):
        log_action("totp_failed", f"Failed TOTP for API host removal: {host}", "API", "warning")
        raise HTTPException(status_code=401, detail="Invalid TOTP code")
    
    if delete_api_host(host):
        notify_host_removed(host)
        log_action("host_removed", f"API: {host}", "API", "warning")
        return {"status": "removed"}
    
    return JSONResponse(
        status_code=404,
        content={"status": "not_found"}
    )


@app.patch("/hosts/api/{host}")
async def toggle_api_host_endpoint(
    request: Request,
    host: str,
    totp: TOTPRequest,
    authenticated: bool = Depends(verify_static_token)
):
    """Enable/disable API host (requires TOTP)."""
    await track_request(request)
    
    if not verify_totp(totp.code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")
    
    hosts = get_all_api_hosts(enabled_only=False)
    current_host = next((h for h in hosts if h["host"] == host), None)
    
    if not current_host:
        return JSONResponse(status_code=404, content={"status": "not_found"})
    
    new_state = not current_host["enabled"]
    
    if toggle_api_host(host, new_state):
        log_action("host_toggled", f"API: {host} -> {'enabled' if new_state else 'disabled'}", "API", "info")
        return {"status": "updated", "enabled": new_state}
    
    return JSONResponse(status_code=500, content={"status": "error"})


@app.post("/action")
async def execute_shutdown(
    request: Request,
    totp: TOTPRequest,
    authenticated: bool = Depends(verify_static_token)
):
    """Execute emergency shutdown (requires TOTP)."""
    await track_request(request)
    
    if not verify_totp(totp.code):
        log_action("totp_failed", "Invalid TOTP for shutdown", "API", "error")
        raise HTTPException(status_code=401, detail="Invalid TOTP code")
    
    if is_shutdown_in_progress():
        return JSONResponse(
            status_code=409,
            content={"status": "in_progress", "details": get_shutdown_status()}
        )
    
    notify_shutdown()
    log_action("shutdown_initiated", "Emergency shutdown triggered", "API", "critical")
    
    result = initiate_hard_poweroff()
    return result


@app.get("/status")
async def shutdown_status(authenticated: bool = Depends(verify_static_token)):
    """Get shutdown operation status."""
    status = get_shutdown_status()
    return {"status": "ok", "shutdown": status}


@app.get("/logs")
async def get_logs(
    request: Request,
    limit: int = 100,
    authenticated: bool = Depends(verify_static_token)
):
    """Retrieve audit logs."""
    await track_request(request)
    
    logs = get_all_logs(limit)
    return {
        "status": "ok",
        "count": len(logs),
        "logs": logs
    }


@app.get("/sessions")
async def get_sessions(
    request: Request,
    limit: int = 50,
    authenticated: bool = Depends(verify_static_token)
):
    """Retrieve session history."""
    await track_request(request)
    
    sessions = get_recent_sessions(limit)
    return {
        "status": "ok",
        "count": len(sessions),
        "sessions": sessions
    }


if __name__ == "__main__":
    # Ensure DB exists before preflight to avoid table-missing warnings
    try:
        from database import init_db as _init_db
        _init_db()
    except Exception:
        pass
    # Preflight: ensure MASTER_SECRET is configured to avoid lifespan errors
    from auth import preflight_check
    ready = preflight_check()
    if not ready:
        raise SystemExit(0)
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
