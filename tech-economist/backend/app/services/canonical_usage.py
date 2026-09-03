"""Canonical token usage normalization and pricing (Cost & Token-Usage Accounting)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from app.services.pricing import MODEL_COSTS, ModelCosts, get_model_costs
from app.services.rust_core import run_rust_core


@dataclass
class CanonicalUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    web_search_requests: int = 0

    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_input_tokens
            + self.cache_creation_input_tokens
        )


@dataclass
class CostBreakdown:
    model: str
    usage: CanonicalUsage
    input_cost_usd: float
    output_cost_usd: float
    cache_read_cost_usd: float
    cache_write_cost_usd: float
    web_search_cost_usd: float
    total_cost_usd: float
    pricing_tier: str = "canonical"
    unknown_model: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "usage": {
                "input_tokens": self.usage.input_tokens,
                "output_tokens": self.usage.output_tokens,
                "cache_read_input_tokens": self.usage.cache_read_input_tokens,
                "cache_creation_input_tokens": self.usage.cache_creation_input_tokens,
                "web_search_requests": self.usage.web_search_requests,
                "total_tokens": self.usage.total_tokens(),
            },
            "input_cost_usd": round(self.input_cost_usd, 8),
            "output_cost_usd": round(self.output_cost_usd, 8),
            "cache_read_cost_usd": round(self.cache_read_cost_usd, 8),
            "cache_write_cost_usd": round(self.cache_write_cost_usd, 8),
            "web_search_cost_usd": round(self.web_search_cost_usd, 8),
            "total_cost_usd": round(self.total_cost_usd, 8),
            "pricing_tier": self.pricing_tier,
            "unknown_model": self.unknown_model,
        }


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def from_openai_usage(usage: Dict[str, Any]) -> CanonicalUsage:
    details = usage.get("prompt_tokens_details") or {}
    cached = _int(details.get("cached_tokens"))
    return CanonicalUsage(
        input_tokens=max(0, _int(usage.get("prompt_tokens")) - cached),
        output_tokens=_int(usage.get("completion_tokens")),
        cache_read_input_tokens=cached,
        cache_creation_input_tokens=0,
    )


def from_anthropic_usage(usage: Dict[str, Any]) -> CanonicalUsage:
    return CanonicalUsage(
        input_tokens=_int(usage.get("input_tokens")),
        output_tokens=_int(usage.get("output_tokens")),
        cache_read_input_tokens=_int(usage.get("cache_read_input_tokens")),
        cache_creation_input_tokens=_int(usage.get("cache_creation_input_tokens")),
    )


def from_canonical_payload(payload: Dict[str, Any]) -> CanonicalUsage:
    return CanonicalUsage(
        input_tokens=_int(payload.get("input_tokens")),
        output_tokens=_int(payload.get("output_tokens")),
        cache_read_input_tokens=_int(payload.get("cache_read_input_tokens")),
        cache_creation_input_tokens=_int(payload.get("cache_creation_input_tokens")),
        web_search_requests=_int(payload.get("web_search_requests")),
    )


def normalize_usage(provider: str, usage: Dict[str, Any]) -> CanonicalUsage:
    rust_value = run_rust_core("canonical-usage", {"provider": provider, "usage": usage})
    if isinstance(rust_value, dict):
        return CanonicalUsage(
            input_tokens=int(rust_value.get("input_tokens", 0)),
            output_tokens=int(rust_value.get("output_tokens", 0)),
            cache_read_input_tokens=int(rust_value.get("cache_read_input_tokens", 0)),
            cache_creation_input_tokens=int(rust_value.get("cache_creation_input_tokens", 0)),
            web_search_requests=int(rust_value.get("web_search_requests", 0)),
        )

    provider_key = (provider or "canonical").lower()
    if provider_key in ("openai", "openrouter", "azure"):
        return from_openai_usage(usage)
    if provider_key in ("anthropic", "claude"):
        return from_anthropic_usage(usage)
    if provider_key == "canonical":
        return from_canonical_payload(usage)
    # Best-effort: accept either shape
    if "prompt_tokens" in usage or "completion_tokens" in usage:
        return from_openai_usage(usage)
    if "input_tokens" in usage:
        return from_anthropic_usage(usage)
    return from_canonical_payload(usage)


def price_usage(model: str, usage: CanonicalUsage) -> CostBreakdown:
    rust_value = run_rust_core(
        "price-usage",
        {
            "model": model,
            "usage": {
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "cache_read_input_tokens": usage.cache_read_input_tokens,
                "cache_creation_input_tokens": usage.cache_creation_input_tokens,
                "web_search_requests": usage.web_search_requests,
            },
        },
    )
    if isinstance(rust_value, dict):
        rust_usage = rust_value.get("usage") or {}
        return CostBreakdown(
            model=str(rust_value.get("model", model)),
            usage=CanonicalUsage(
                input_tokens=int(rust_usage.get("input_tokens", 0)),
                output_tokens=int(rust_usage.get("output_tokens", 0)),
                cache_read_input_tokens=int(rust_usage.get("cache_read_input_tokens", 0)),
                cache_creation_input_tokens=int(rust_usage.get("cache_creation_input_tokens", 0)),
                web_search_requests=int(rust_usage.get("web_search_requests", 0)),
            ),
            input_cost_usd=float(rust_value.get("input_cost_usd", 0.0)),
            output_cost_usd=float(rust_value.get("output_cost_usd", 0.0)),
            cache_read_cost_usd=float(rust_value.get("cache_read_cost_usd", 0.0)),
            cache_write_cost_usd=float(rust_value.get("cache_write_cost_usd", 0.0)),
            web_search_cost_usd=float(rust_value.get("web_search_cost_usd", 0.0)),
            total_cost_usd=float(rust_value.get("total_cost_usd", 0.0)),
            pricing_tier=str(rust_value.get("pricing_tier", "canonical")),
            unknown_model=bool(rust_value.get("unknown_model", False)),
        )

    costs: ModelCosts = get_model_costs(model)
    unknown = canonical_model_name(model) not in MODEL_COSTS

    input_cost = usage.input_tokens / 1_000_000 * costs.input_tokens
    output_cost = usage.output_tokens / 1_000_000 * costs.output_tokens
    cache_read_cost = usage.cache_read_input_tokens / 1_000_000 * costs.prompt_cache_read_tokens
    cache_write_cost = (
        usage.cache_creation_input_tokens / 1_000_000 * costs.prompt_cache_write_tokens
    )
    web_cost = usage.web_search_requests * costs.web_search_requests
    total = input_cost + output_cost + cache_read_cost + cache_write_cost + web_cost

    return CostBreakdown(
        model=model,
        usage=usage,
        input_cost_usd=input_cost,
        output_cost_usd=output_cost,
        cache_read_cost_usd=cache_read_cost,
        cache_write_cost_usd=cache_write_cost,
        web_search_cost_usd=web_cost,
        total_cost_usd=total,
        pricing_tier="canonical",
        unknown_model=unknown,
    )


def canonical_model_name(model: str) -> str:
    return model.strip().lower()
