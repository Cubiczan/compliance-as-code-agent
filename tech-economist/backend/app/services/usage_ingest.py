"""Persist and aggregate canonical usage ingest events."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import UsageIngestRecord
from app.services.canonical_usage import CanonicalUsage, CostBreakdown, normalize_usage, price_usage
from app.services.rust_core import run_rust_core


def ingest_usage(
    db: Session,
    *,
    session_id: str,
    source: str,
    model: str,
    provider: str,
    usage: Dict[str, Any],
    workflow_id: Optional[int] = None,
    agent_id: Optional[str] = None,
    tool_call_id: Optional[str] = None,
) -> tuple[UsageIngestRecord, CostBreakdown]:
    canonical = normalize_usage(provider, usage)
    priced = price_usage(model, canonical)

    record = UsageIngestRecord(
        session_id=session_id,
        source=source,
        workflow_id=workflow_id,
        agent_id=agent_id,
        tool_call_id=tool_call_id,
        model=model,
        provider=provider,
        input_tokens=canonical.input_tokens,
        output_tokens=canonical.output_tokens,
        cache_read_input_tokens=canonical.cache_read_input_tokens,
        cache_creation_input_tokens=canonical.cache_creation_input_tokens,
        web_search_requests=canonical.web_search_requests,
        input_cost_usd=priced.input_cost_usd,
        output_cost_usd=priced.output_cost_usd,
        cache_read_cost_usd=priced.cache_read_cost_usd,
        cache_write_cost_usd=priced.cache_write_cost_usd,
        web_search_cost_usd=priced.web_search_cost_usd,
        total_cost_usd=priced.total_cost_usd,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record, priced


def session_cost_summary(db: Session, session_id: str) -> Dict[str, Any]:
    rows: List[UsageIngestRecord] = (
        db.query(UsageIngestRecord)
        .filter(UsageIngestRecord.session_id == session_id)
        .order_by(UsageIngestRecord.recorded_at.asc())
        .all()
    )

    rust_value = run_rust_core(
        "session-summary",
        {
            "session_id": session_id,
            "records": [
                {
                    "session_id": r.session_id,
                    "source": r.source,
                    "workflow_id": r.workflow_id,
                    "agent_id": r.agent_id,
                    "tool_call_id": r.tool_call_id,
                    "model": r.model,
                    "provider": r.provider,
                    "input_tokens": r.input_tokens,
                    "output_tokens": r.output_tokens,
                    "cache_read_input_tokens": r.cache_read_input_tokens,
                    "cache_creation_input_tokens": r.cache_creation_input_tokens,
                    "total_cost_usd": r.total_cost_usd,
                    "recorded_at": r.recorded_at.isoformat(),
                }
                for r in rows
            ],
        },
    )
    if isinstance(rust_value, dict):
        return rust_value

    if not rows:
        return {
            "session_id": session_id,
            "call_count": 0,
            "total_cost_usd": 0.0,
            "total_tokens": 0,
            "by_model": {},
            "by_agent": {},
            "records": [],
        }

    by_model: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cost_usd": 0.0,
            "calls": 0,
        }
    )
    by_agent: Dict[str, float] = defaultdict(float)
    total_cost = 0.0
    total_tokens = 0

    for row in rows:
        bucket = by_model[row.model]
        bucket["input_tokens"] += row.input_tokens
        bucket["output_tokens"] += row.output_tokens
        bucket["cache_read_input_tokens"] += row.cache_read_input_tokens
        bucket["cache_creation_input_tokens"] += row.cache_creation_input_tokens
        bucket["cost_usd"] += row.total_cost_usd
        bucket["calls"] += 1

        if row.agent_id:
            by_agent[row.agent_id] += row.total_cost_usd

        total_cost += row.total_cost_usd
        total_tokens += (
            row.input_tokens
            + row.output_tokens
            + row.cache_read_input_tokens
            + row.cache_creation_input_tokens
        )

    return {
        "session_id": session_id,
        "source": rows[0].source,
        "workflow_id": rows[0].workflow_id,
        "call_count": len(rows),
        "total_cost_usd": round(total_cost, 8),
        "total_tokens": total_tokens,
        "by_model": {k: {**v, "cost_usd": round(v["cost_usd"], 8)} for k, v in by_model.items()},
        "by_agent": {k: round(v, 8) for k, v in by_agent.items()},
        "first_recorded_at": rows[0].recorded_at.isoformat(),
        "last_recorded_at": rows[-1].recorded_at.isoformat(),
    }
