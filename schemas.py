# backend/app/schemas.py
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    vulnerability_type: str
    severity: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    status: str
    overall_score: Optional[int] = None
    scan_date: datetime
    open_ports: List[Dict[str, Any]] = []
    dns_security_records: Dict[str, str] = {}
    https_enforced: Optional[bool] = None
    vulnerabilities: List[VulnerabilityOut] = []


class ScanSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    overall_score: Optional[int] = None
    scan_date: datetime