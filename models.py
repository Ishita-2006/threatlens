from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    domain_or_ip = Column(String, unique=True, index=True, nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship(
        "Scan",
        back_populates="target",
        cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="pending")
    overall_score = Column(Integer, nullable=True)

    # NEW: raw findings, so a scan's full detail can be retrieved later via
    # GET /api/v1/scans/{id}, not just at the moment it was created.
    open_ports = Column(JSON, nullable=True)
    dns_records = Column(JSON, nullable=True)
    https_enforced = Column(Boolean, nullable=True)

    target = relationship("Target", back_populates="scans")
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    vulnerability_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text)
    remediation = Column(Text)

    scan = relationship("Scan", back_populates="vulnerabilities")
    