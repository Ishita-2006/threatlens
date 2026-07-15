# backend/app/routers/scans.py
import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..schemas import ScanOut, ScanSummaryOut
from ..services.scan_service import InvalidTargetError, run_scan, validate_target

logger = logging.getLogger("threatlens")

router = APIRouter(prefix="/api/v1", tags=["scans"])


def _to_scan_out(scan: models.Scan) -> ScanOut:
    return ScanOut(
        id=scan.id,
        target=scan.target.domain_or_ip,
        status=scan.status,
        overall_score=scan.overall_score,
        scan_date=scan.scan_date,
        open_ports=scan.open_ports or [],
        dns_security_records=scan.dns_records or {},
        https_enforced=scan.https_enforced,
        vulnerabilities=scan.vulnerabilities,
    )


@router.post("/scans/{domain}", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(domain: str, db: Session = Depends(get_db)):
    """Runs a new passive security scan against `domain` and persists the result.

    Replaces the old `GET /test-scan/{domain}`. A scan makes live outbound
    requests and writes new rows to the database -- that's a side effect,
    not a read -- so per REST conventions this is a POST that creates a new
    Scan resource, not a GET.
    """
    try:
        await asyncio.to_thread(validate_target, domain)
    except InvalidTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        scan = await run_scan(domain, db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed for {domain}: {exc}") from exc

    return _to_scan_out(scan)


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Retrieves a previously completed scan by ID."""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return _to_scan_out(scan)


@router.get("/targets/{domain}/scans", response_model=list[ScanSummaryOut])
def list_scans_for_target(domain: str, db: Session = Depends(get_db)):
    """Lists scan history for a target.

    Returns an empty list (200) rather than 404 if the target has never
    been scanned -- the collection is simply empty, which is the more
    RESTful response than treating "no history yet" as an error.
    """
    target = db.query(models.Target).filter(models.Target.domain_or_ip == domain).first()
    if target is None:
        return []
    return [
        ScanSummaryOut(id=s.id, status=s.status, overall_score=s.overall_score, scan_date=s.scan_date)
        for s in sorted(target.scans, key=lambda s: s.scan_date, reverse=True)
    ]