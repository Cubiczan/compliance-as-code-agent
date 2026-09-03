from __future__ import annotations

from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import EnterpriseConfig, MonthlySnapshot, UsageEvent, Workflow
from app.schemas import (
    DashboardSummary,
    ForecastPoint,
    MonthlyTrend,
    RoiScenarioRequest,
    RoiScenarioResponse,
    WorkflowEconomics,
    WorkflowOut,
)
from app.services.benchmarks import INDUSTRY_BENCHMARKS
from app.services.rust_core import run_rust_core
from app.services.tokencost_service import estimate_cost


def _get_or_create_config(db: Session) -> EnterpriseConfig:
    config = db.query(EnterpriseConfig).first()
    if not config:
        config = EnterpriseConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


def _workflow_payload(wf: Workflow) -> dict:
    return {
        "id": wf.id,
        "name": wf.name,
        "category": wf.category,
        "department": wf.department,
        "description": wf.description,
        "default_model": wf.default_model,
        "manual_baseline_cost_usd": wf.manual_baseline_cost_usd,
        "expected_value_per_success_usd": wf.expected_value_per_success_usd,
        "benchmark_roi_median": wf.benchmark_roi_median,
        "benchmark_cost_per_task_usd": wf.benchmark_cost_per_task_usd,
        "is_strategic": wf.is_strategic,
    }


def _usage_event_payload(event: UsageEvent) -> dict:
    return {
        "workflow_id": event.workflow_id,
        "total_cost_usd": event.total_cost_usd,
        "revenue_lift_usd": event.revenue_lift_usd,
        "successful": event.successful,
        "prompt_tokens": event.prompt_tokens,
        "completion_tokens": event.completion_tokens,
    }


def _benchmark_payload() -> list[dict]:
    return [b.model_dump() for b in INDUSTRY_BENCHMARKS]


def compute_eps_impact(config: EnterpriseConfig, net_value_usd: float) -> tuple[float, float]:
    rust_value = run_rust_core(
        "eps-impact",
        {
            "config": {
                "shares_outstanding_millions": config.shares_outstanding_millions,
                "annual_tech_investment_billions": config.annual_tech_investment_billions,
                "earnings_per_share": config.earnings_per_share,
            },
            "net_value_usd": net_value_usd,
        },
    )
    if isinstance(rust_value, dict):
        return (
            float(rust_value.get("eps_impact_per_share_usd", 0.0)),
            float(rust_value.get("eps_at_risk_pct", 0.0)),
        )

    shares = config.shares_outstanding_millions * 1_000_000
    eps_impact = net_value_usd / shares if shares else 0.0
    tech_load = config.annual_tech_investment_billions * 1_000_000_000
    eps_at_risk_pct = (tech_load / shares / config.earnings_per_share * 100) if config.earnings_per_share else 0.0
    return round(eps_impact, 4), round(eps_at_risk_pct, 2)


def get_dashboard_summary(db: Session) -> DashboardSummary:
    config = _get_or_create_config(db)
    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    year_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)

    mtd_events = db.query(UsageEvent).filter(UsageEvent.recorded_at >= month_start).all()
    ytd_events = db.query(UsageEvent).filter(UsageEvent.recorded_at >= year_start).all()
    workflow_stats = get_workflow_economics(db)
    rust_value = run_rust_core(
        "dashboard-summary",
        {
            "config": {
                "shares_outstanding_millions": config.shares_outstanding_millions,
                "annual_tech_investment_billions": config.annual_tech_investment_billions,
                "earnings_per_share": config.earnings_per_share,
                "ai_compute_budget_millions": config.ai_compute_budget_millions,
                "month": now.month,
            },
            "mtd_events": [_usage_event_payload(e) for e in mtd_events],
            "ytd_events": [_usage_event_payload(e) for e in ytd_events],
            "workflow_economics": [w.model_dump() for w in workflow_stats],
            "benchmarks": _benchmark_payload(),
        },
    )
    if isinstance(rust_value, dict):
        return DashboardSummary(
            total_spend_mtd_usd=float(rust_value.get("total_spend_mtd_usd", 0.0)),
            total_spend_ytd_usd=float(rust_value.get("total_spend_ytd_usd", 0.0)),
            portfolio_roi=float(rust_value.get("portfolio_roi", 0.0)),
            cost_per_successful_task_usd=float(rust_value.get("cost_per_successful_task_usd", 0.0)),
            successful_tasks_mtd=int(rust_value.get("successful_tasks_mtd", 0)),
            failed_tasks_mtd=int(rust_value.get("failed_tasks_mtd", 0)),
            success_rate_pct=float(rust_value.get("success_rate_pct", 0.0)),
            ai_budget_utilization_pct=float(rust_value.get("ai_budget_utilization_pct", 0.0)),
            revenue_lift_mtd_usd=float(rust_value.get("revenue_lift_mtd_usd", 0.0)),
            net_value_mtd_usd=float(rust_value.get("net_value_mtd_usd", 0.0)),
            eps_impact_per_share_usd=float(rust_value.get("eps_impact_per_share_usd", 0.0)),
            eps_at_risk_pct=float(rust_value.get("eps_at_risk_pct", 0.0)),
            projected_annual_spend_millions=float(rust_value.get("projected_annual_spend_millions", 0.0)),
            benchmark_median_roi=float(rust_value.get("benchmark_median_roi", 0.0)),
            workflows_underwater=int(rust_value.get("workflows_underwater", 0)),
            workflows_high_leverage=int(rust_value.get("workflows_high_leverage", 0)),
        )

    def aggregate(events: list[UsageEvent]) -> dict:
        spend = sum(e.total_cost_usd for e in events)
        lift = sum(e.revenue_lift_usd for e in events if e.successful)
        successful = sum(1 for e in events if e.successful)
        failed = sum(1 for e in events if not e.successful)
        cost_per_task = spend / successful if successful else 0.0
        roi = lift / spend if spend else 0.0
        return {
            "spend": spend,
            "lift": lift,
            "successful": successful,
            "failed": failed,
            "cost_per_task": cost_per_task,
            "roi": roi,
        }

    mtd = aggregate(mtd_events)
    ytd = aggregate(ytd_events)
    net_value = mtd["lift"] - mtd["spend"]
    eps_impact, eps_at_risk = compute_eps_impact(config, net_value)

    months_elapsed = max(now.month, 1)
    projected_annual = (ytd["spend"] / months_elapsed) * 12 / 1_000_000
    budget_util = (mtd["spend"] / (config.ai_compute_budget_millions * 1_000_000 / 12) * 100) if config.ai_compute_budget_millions else 0.0

    underwater = sum(1 for w in workflow_stats if w.roi_multiple < 1.0)
    high_leverage = sum(1 for w in workflow_stats if w.roi_multiple >= 3.0)

    benchmark_median = sum(b.median_roi for b in INDUSTRY_BENCHMARKS[:8]) / 8

    success_total = mtd["successful"] + mtd["failed"]
    success_rate = (mtd["successful"] / success_total * 100) if success_total else 0.0

    return DashboardSummary(
        total_spend_mtd_usd=round(mtd["spend"], 2),
        total_spend_ytd_usd=round(ytd["spend"], 2),
        portfolio_roi=round(mtd["roi"], 2),
        cost_per_successful_task_usd=round(mtd["cost_per_task"], 4),
        successful_tasks_mtd=mtd["successful"],
        failed_tasks_mtd=mtd["failed"],
        success_rate_pct=round(success_rate, 1),
        ai_budget_utilization_pct=round(min(budget_util, 999), 1),
        revenue_lift_mtd_usd=round(mtd["lift"], 2),
        net_value_mtd_usd=round(net_value, 2),
        eps_impact_per_share_usd=eps_impact,
        eps_at_risk_pct=eps_at_risk,
        projected_annual_spend_millions=round(projected_annual, 2),
        benchmark_median_roi=round(benchmark_median, 2),
        workflows_underwater=underwater,
        workflows_high_leverage=high_leverage,
    )


def get_workflow_economics(db: Session) -> list[WorkflowEconomics]:
    workflows = db.query(Workflow).all()
    events = db.query(UsageEvent).all()

    rust_value = run_rust_core(
        "workflow-economics",
        {
            "workflows": [_workflow_payload(wf) for wf in workflows],
            "usage_events": [_usage_event_payload(e) for e in events],
        },
    )
    if isinstance(rust_value, list):
        return [
            WorkflowEconomics(
                workflow=WorkflowOut.model_validate(item["workflow"]),
                total_spend_usd=float(item.get("total_spend_usd", 0.0)),
                total_revenue_lift_usd=float(item.get("total_revenue_lift_usd", 0.0)),
                successful_runs=int(item.get("successful_runs", 0)),
                failed_runs=int(item.get("failed_runs", 0)),
                cost_per_successful_task_usd=float(item.get("cost_per_successful_task_usd", 0.0)),
                roi_multiple=float(item.get("roi_multiple", 0.0)),
                vs_benchmark_roi=(None if item.get("vs_benchmark_roi") is None else float(item.get("vs_benchmark_roi"))),
                status=str(item.get("status", "uninstrumented")),
            )
            for item in rust_value
        ]

    results = []

    for wf in workflows:
        events = db.query(UsageEvent).filter(UsageEvent.workflow_id == wf.id).all()
        spend = sum(e.total_cost_usd for e in events)
        lift = sum(e.revenue_lift_usd for e in events if e.successful)
        successful = sum(1 for e in events if e.successful)
        failed = sum(1 for e in events if not e.successful)
        cost_per_task = spend / successful if successful else 0.0
        roi = lift / spend if spend else 0.0

        vs_benchmark = None
        if wf.benchmark_roi_median and wf.benchmark_roi_median > 0:
            vs_benchmark = round((roi / wf.benchmark_roi_median - 1) * 100, 1)

        if roi >= 3.0:
            status = "high_leverage"
        elif roi >= 1.0:
            status = "viable"
        elif spend > 0:
            status = "underwater"
        else:
            status = "uninstrumented"

        results.append(
            WorkflowEconomics(
                workflow=WorkflowOut.model_validate(wf),
                total_spend_usd=round(spend, 2),
                total_revenue_lift_usd=round(lift, 2),
                successful_runs=successful,
                failed_runs=failed,
                cost_per_successful_task_usd=round(cost_per_task, 4),
                roi_multiple=round(roi, 2),
                vs_benchmark_roi=vs_benchmark,
                status=status,
            )
        )

    return sorted(results, key=lambda x: x.roi_multiple, reverse=True)


def get_monthly_trends(db: Session) -> list[MonthlyTrend]:
    snapshots = (
        db.query(MonthlySnapshot)
        .order_by(MonthlySnapshot.month)
        .all()
    )
    rust_value = run_rust_core(
        "monthly-trends",
        {
            "snapshots": [
                {
                    "month": s.month,
                    "total_spend_usd": s.total_spend_usd,
                    "total_revenue_lift_usd": s.total_revenue_lift_usd,
                    "portfolio_roi": s.portfolio_roi,
                    "cost_per_successful_task_usd": s.cost_per_successful_task_usd,
                    "successful_tasks": s.successful_tasks,
                    "token_volume_millions": s.token_volume_millions,
                }
                for s in snapshots
            ]
        },
    )
    if isinstance(rust_value, list):
        return [MonthlyTrend(**item) for item in rust_value]

    return [
        MonthlyTrend(
            month=s.month,
            total_spend_usd=s.total_spend_usd,
            total_revenue_lift_usd=s.total_revenue_lift_usd,
            portfolio_roi=s.portfolio_roi,
            cost_per_successful_task_usd=s.cost_per_successful_task_usd,
            successful_tasks=s.successful_tasks,
            token_volume_millions=s.token_volume_millions,
        )
        for s in snapshots
    ]


def generate_forecast(db: Session, months_ahead: int = 6) -> list[ForecastPoint]:
    trends = get_monthly_trends(db)
    rust_value = run_rust_core(
        "forecast",
        {
            "trends": [
                {
                    "month": t.month,
                    "total_spend_usd": t.total_spend_usd,
                    "portfolio_roi": t.portfolio_roi,
                }
                for t in trends
            ],
            "months_ahead": months_ahead,
        },
    )
    if isinstance(rust_value, list):
        return [ForecastPoint(**item) for item in rust_value]

    if len(trends) < 2:
        return []

    recent = trends[-3:]
    avg_spend = sum(t.total_spend_usd for t in recent) / len(recent)
    avg_roi = sum(t.portfolio_roi for t in recent) / len(recent)
    growth = 1.08

    last_month = trends[-1].month
    year, month = map(int, last_month.split("-"))

    forecasts = []
    projected = avg_spend
    for _ in range(months_ahead):
        month += 1
        if month > 12:
            month = 1
            year += 1
        projected *= growth
        label = f"{year:04d}-{month:02d}"
        forecasts.append(
            ForecastPoint(
                month=label,
                projected_spend_usd=round(projected, 2),
                projected_roi=round(avg_roi * 0.98, 2),
                confidence_low_usd=round(projected * 0.85, 2),
                confidence_high_usd=round(projected * 1.25, 2),
            )
        )
    return forecasts


def run_roi_scenario(req: RoiScenarioRequest) -> RoiScenarioResponse:
    rust_value = run_rust_core("roi-scenario", req.model_dump())
    if isinstance(rust_value, dict):
        return RoiScenarioResponse(**rust_value)

    prompt = "x" * req.avg_prompt_tokens
    completion = "x" * req.avg_completion_tokens
    per_run = estimate_cost(req.model, prompt, completion)
    successful_runs = req.annual_runs * req.success_rate
    annual_token_cost = per_run["total_cost_usd"] * req.annual_runs * 1.85

    labor_value = req.avg_hours_saved * req.hourly_cost_usd * successful_runs
    revenue_value = req.avg_revenue_lift_usd * successful_runs
    manual_savings = req.manual_baseline_cost_usd * successful_runs
    annual_value = labor_value + revenue_value + manual_savings
    net_value = annual_value - annual_token_cost
    roi = annual_value / annual_token_cost if annual_token_cost else 0.0
    cost_per_task = annual_token_cost / successful_runs if successful_runs else 0.0

    payback = None
    if net_value > 0 and annual_token_cost > 0:
        payback = round(annual_token_cost / (net_value / 12), 1)

    if roi >= 5:
        rec = "Strategic investment — scale with governance and model routing."
    elif roi >= 2:
        rec = "Viable — optimize with caching and medium reasoning effort."
    elif roi >= 1:
        rec = "Marginal — require outcome attribution before expanding."
    else:
        rec = "Underwater — pause scaling; fix success rate or switch models."

    return RoiScenarioResponse(
        annual_token_cost_usd=round(annual_token_cost, 2),
        annual_value_usd=round(annual_value, 2),
        annual_net_value_usd=round(net_value, 2),
        roi_multiple=round(roi, 2),
        payback_months=payback,
        cost_per_successful_task_usd=round(cost_per_task, 4),
        recommendation=rec,
    )


def refresh_monthly_snapshot(db: Session, month: str) -> None:
    events = (
        db.query(UsageEvent)
        .filter(func.strftime("%Y-%m", UsageEvent.recorded_at) == month)
        .all()
    )
    if not events:
        return

    rust_value = run_rust_core(
        "monthly-snapshot",
        {
            "events": [
                {
                    "total_cost_usd": e.total_cost_usd,
                    "revenue_lift_usd": e.revenue_lift_usd,
                    "successful": e.successful,
                    "prompt_tokens": e.prompt_tokens,
                    "completion_tokens": e.completion_tokens,
                }
                for e in events
            ]
        },
    )
    if isinstance(rust_value, dict):
        spend = float(rust_value.get("total_spend_usd", 0.0))
        lift = float(rust_value.get("total_revenue_lift_usd", 0.0))
        successful = int(rust_value.get("successful_tasks", 0))
        failed = int(rust_value.get("failed_tasks", 0))
        cost_per_task = float(rust_value.get("cost_per_successful_task_usd", 0.0))
        roi = float(rust_value.get("portfolio_roi", 0.0))
        tokens = float(rust_value.get("token_volume_millions", 0.0))
    else:
        spend = sum(e.total_cost_usd for e in events)
        lift = sum(e.revenue_lift_usd for e in events if e.successful)
        successful = sum(1 for e in events if e.successful)
        failed = sum(1 for e in events if not e.successful)
        tokens = sum(e.prompt_tokens + e.completion_tokens for e in events) / 1_000_000
        cost_per_task = spend / successful if successful else 0.0
        roi = lift / spend if spend else 0.0

    snapshot = db.query(MonthlySnapshot).filter(MonthlySnapshot.month == month).first()
    if not snapshot:
        snapshot = MonthlySnapshot(month=month)
        db.add(snapshot)

    snapshot.total_spend_usd = round(spend, 2)
    snapshot.total_revenue_lift_usd = round(lift, 2)
    snapshot.successful_tasks = successful
    snapshot.failed_tasks = failed
    snapshot.cost_per_successful_task_usd = round(cost_per_task, 4)
    snapshot.portfolio_roi = round(roi, 2)
    snapshot.token_volume_millions = round(tokens, 3)
    db.commit()
