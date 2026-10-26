
from fastapi import HTTPException
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import sqlite3
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "securetech.db"

app = FastAPI(
    title="SecureTech Risk Assessment API",
    description="Cybersecurity assessment for the SecureTech Solutions lab",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to the frontend origin before deployment.
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def record_audit(connection, action, details):
    connection.execute(
        "INSERT INTO audit_log (action, details, created_at) VALUES (?, ?, ?)",
        (action, details, datetime.now(timezone.utc).isoformat()),
    )


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/api/health")
def health():
    return {"status": "ok", "application": "SecureTech"}


@app.get("/api/assets")
def assets():
    return {
        "assets": [
            {
                "name": "SecureTech Ubuntu Server",
                "ip": "192.168.50.10",
                "type": "Linux server",
                "environment": "Isolated lab",
            }
        ]
    }


@app.get("/api/findings")
def list_findings():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM findings ORDER BY id DESC"
        ).fetchall()
    return {"findings": [dict(row) for row in rows]}


@app.get("/api/summary")
def summary():
    with get_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]
        open_count = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE status = 'Open'"
        ).fetchone()[0]
        severity_rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity"
        ).fetchall()

    return {
        "total_findings": total,
        "open_findings": open_count,
        "by_severity": {
            row["severity"]: row["count"] for row in severity_rows
        },
    }


class SimulatedEvent(BaseModel):
    event_type: str = "Failed login"
    source: str = "192.168.50.20"
    count: int = 5


@app.post("/api/simulate")
def simulate_event(event: SimulatedEvent):
    # This endpoint records a clearly labelled simulation, not a real attack.
    count = max(1, min(event.count, 1000))
    title = f"SIMULATED: {event.event_type}"
    description = (
        f"Training event only. Source={event.source}; "
        f"simulated event count={count}. No attack was executed."
    )

    with get_connection() as connection:
        connection.execute(
            """INSERT INTO findings
            (asset, category, title, severity, description,
             recommendation, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'Open', ?)""",
            (
                "SecureTech Ubuntu Server",
                "Threat simulation",
                title,
                "Medium",
                description,
                "Review authentication logs and apply account lockout "
                "and multi-factor authentication policies where appropriate.",
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        record_audit(connection, "SIMULATION_CREATED", description)

    return {"message": "Simulation recorded", "title": title}


@app.get("/api/audit")
def audit_records():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return {"audit_records": [dict(row) for row in rows]}



@app.post("/api/scan")
def scan_ubuntu_server():
    target = "192.168.26.10"

    try:
        result = subprocess.run(
            [
                "nmap",
                "-sV",
                "-T3",
                "--top-ports", "100",
                "-oX", "-",
                target,
            ],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "message": result.stderr or "Nmap scan failed",
            }

        root = ET.fromstring(result.stdout)
        host = root.find("host")

        if host is None:
            return {
                "status": "error",
                "message": "No host information returned by Nmap",
            }

        status_element = host.find("status")
        host_status = (
            status_element.get("state", "unknown")
            if status_element is not None
            else "unknown"
        )

        ports = []
        for port in host.findall(".//port"):
            state_element = port.find("state")
            if state_element is None or state_element.get("state") != "open":
                continue

            service = port.find("service")
            ports.append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": service.get("name", "unknown")
                if service is not None else "unknown",
                "version": service.get("version", "")
                if service is not None else "",
            })

        with get_connection() as connection:
            record_audit(
                connection,
                "NMAP_SCAN",
                f"Scanned authorized lab target {target}; "
                f"host status={host_status}; open ports={len(ports)}",
            )

        return {
            "status": "completed",
            "target": target,
            "host_status": host_status,
            "open_ports": ports,
            "note": "Service discovery only; this is not a full vulnerability scan.",
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "Nmap was not found. Add its installation directory to PATH.",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": "Scan timed out after 90 seconds.",
        }
    except ET.ParseError:
        return {
            "status": "error",
            "message": "Could not parse Nmap output.",
        }



# --- Security Posture Score ---

@app.get("/api/posture")
def security_posture():
    weights = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Info": 0,
    }

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM findings "
            "WHERE status != 'Resolved' GROUP BY severity"
        ).fetchall()

    counts = {row["severity"]: row["count"] for row in rows}
    penalty = sum(
        weights.get(severity, 5) * count
        for severity, count in counts.items()
    )
    score = max(0, 100 - penalty)

    if score >= 90:
        rating = "Good"
    elif score >= 70:
        rating = "Moderate"
    elif score >= 40:
        rating = "Poor"
    else:
        rating = "Critical"

    return {
        "score": score,
        "rating": rating,
        "unresolved_findings": sum(counts.values()),
        "severity_counts": counts,
        "method": (
            "Starting score 100 minus severity penalties per unresolved "
            "finding. This is a prototype indicator, not a certified "
            "security rating."
        ),
    }


# --- Finding Remediation Workflow ---

class FindingStatusUpdate(BaseModel):
    status: str


@app.patch("/api/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    update: FindingStatusUpdate,
):
    allowed_statuses = {"Open", "In Progress", "Resolved"}

    if update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Status must be Open, In Progress, or Resolved.",
        )

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id, title, status FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()

        if existing is None:
            raise HTTPException(
                status_code=404,
                detail="Finding not found.",
            )

        old_status = existing["status"]

        connection.execute(
            "UPDATE findings SET status = ? WHERE id = ?",
            (update.status, finding_id),
        )

        record_audit(
            connection,
            "FINDING_STATUS_CHANGED",
            f"Finding #{finding_id} '{existing['title']}': "
            f"{old_status} -> {update.status}",
        )

    return {
        "message": "Finding status updated",
        "finding_id": finding_id,
        "status": update.status,
    }
