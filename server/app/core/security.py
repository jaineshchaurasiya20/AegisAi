"""
AegisAI Security — JWT Token creation & validation, password hashing.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
# pyrefly: ignore [missing-import]
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.core.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# --- Demo user store (replace with DB in production) ---
DEMO_USERS = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("aegis2024"),
        "role": "admin",
    }
}


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = DEMO_USERS.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = DEMO_USERS.get(username)
    if user is None:
        raise credentials_exception
    return user


# =============================================================================
# Process Identity & System Safety Guardrails
# =============================================================================
import os
import psutil
from typing import Tuple


def is_aegisai_self(pid: int) -> bool:
    """Check if the PID belongs to the current AegisAI server process or its runtime."""
    try:
        current_pid = os.getpid()
        if pid == current_pid:
            return True
        # Check parent process if accessible
        if psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            if proc.ppid() == current_pid:
                return True
            # Protect Python process running AegisAI
            cmdline = " ".join(proc.cmdline()).lower()
            if "aegis" in cmdline or "main.py" in cmdline:
                return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return False


def is_protected_process(pid: int, name: Optional[str] = None) -> Tuple[bool, str]:
    """
    Check if a process is protected against destructive remediation.
    Guards AegisAI itself, OS kernel processes, and configured critical services.
    """
    if not pid or pid <= 4:
        return True, f"System critical PID {pid}"

    if is_aegisai_self(pid):
        return True, f"PID {pid} is AegisAI itself"

    protected_set = set(p.lower() for p in settings.PROTECTED_PROCESSES)

    # Check explicit name if supplied
    if name and name.lower() in protected_set:
        return True, f"Protected process name '{name}'"

    # Inspect live process if alive
    try:
        if psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()
            if proc_name in protected_set:
                return True, f"Protected system binary '{proc_name}'"
            if is_aegisai_self(pid):
                return True, f"PID {pid} is AegisAI runtime"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return False, ""


def validate_process_identity(
    pid: int,
    expected_name: Optional[str] = None,
    expected_create_time: Optional[float] = None,
    expected_exe: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Thorough multi-factor process identity validation immediately prior to destructive action.
    Returns (is_valid: bool, reason_or_error: str).
    Guarantees:
      1. PID exists in OS kernel process table.
      2. Process is not AegisAI itself.
      3. Process is not in protected list.
      4. Process name matches investigated target (prevents PID reuse race condition).
      5. Process creation time matches investigated target if known.
    """
    if not pid or pid <= 4:
        return False, "INVALID_PID"

    if is_aegisai_self(pid):
        return False, "AegisAI_SELF_KILL_PREVENTED"

    protected, reason = is_protected_process(pid, expected_name)
    if protected:
        return False, f"PROTECTED_PROCESS: {reason}"

    try:
        if not psutil.pid_exists(pid):
            return False, "PROCESS_DOES_NOT_EXIST"

        proc = psutil.Process(pid)
        proc_name = proc.name().lower()

        # Re-check live name against protected list
        protected, reason = is_protected_process(pid, proc_name)
        if protected:
            return False, f"PROTECTED_PROCESS: {reason}"

        # Confirm process name matches expected
        if expected_name and proc_name != expected_name.lower():
            return False, f"PID_IDENTITY_CHANGED: Expected '{expected_name}', active process is '{proc_name}'"

        # Confirm process creation time if tracked (within 1 second delta)
        if expected_create_time is not None:
            live_create_time = proc.create_time()
            if abs(live_create_time - expected_create_time) > 1.5:
                return False, f"PID_IDENTITY_CHANGED: Creation time mismatch ({live_create_time} != {expected_create_time})"

        # Confirm executable path if tracked
        if expected_exe:
            try:
                live_exe = proc.exe().lower()
                if live_exe != expected_exe.lower():
                    return False, f"PID_IDENTITY_CHANGED: Executable path mismatch"
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

        return True, "IDENTITY_VERIFIED"

    except psutil.NoSuchProcess:
        return False, "PROCESS_ALREADY_TERMINATED"
    except psutil.AccessDenied:
        return False, "ACCESS_DENIED_TO_PROCESS"
    except Exception as e:
        return False, f"IDENTITY_VALIDATION_ERROR: {e}"

