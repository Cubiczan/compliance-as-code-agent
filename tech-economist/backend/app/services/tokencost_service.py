from typing import Dict, List, Union

from tokencost import (
    calculate_completion_cost,
    calculate_prompt_cost,
    count_message_tokens,
    count_string_tokens,
)
from tokencost.constants import TOKEN_COSTS

from app.services.rust_core import run_rust_core

# Fallback per-1M token rates when tiktoken encodings are unavailable offline
FALLBACK_RATES = {
    "gpt-4o": {"input": 2.5, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.6},
    "claude-3-5-sonnet-20241022": {"input": 3.0, "output": 15.0},
    "o1-mini": {"input": 1.1, "output": 4.4},
}


def _approx_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _resolve_rates(model: str) -> Dict[str, float]:
    model_key = model.lower()
    if model_key in TOKEN_COSTS:
        costs = TOKEN_COSTS[model_key]
        return {
            "input": float(costs.get("input_cost_per_token", 0)) * 1_000_000,
            "output": float(costs.get("output_cost_per_token", 0)) * 1_000_000,
        }
    for key, rates in FALLBACK_RATES.items():
        if key in model_key:
            return rates
    return {"input": 1.0, "output": 2.0}


def _fallback_estimate(model: str, prompt: Union[str, List[Dict]], completion: str) -> dict:
    if isinstance(prompt, list):
        prompt_text = " ".join(
            m.get("content", "") if isinstance(m.get("content"), str) else str(m.get("content", ""))
            for m in prompt
        )
    else:
        prompt_text = prompt

    prompt_tokens = _approx_tokens(prompt_text)
    completion_tokens = _approx_tokens(completion) if completion else 0
    rates = _resolve_rates(model)

    prompt_cost = prompt_tokens * rates["input"] / 1_000_000
    completion_cost = completion_tokens * rates["output"] / 1_000_000
    total_cost = prompt_cost + completion_cost
    total_tokens = prompt_tokens + completion_tokens

    return {
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "prompt_cost_usd": round(prompt_cost, 8),
        "completion_cost_usd": round(completion_cost, 8),
        "total_cost_usd": round(total_cost, 8),
        "cost_per_1m_tokens_usd": round(total_cost / total_tokens * 1_000_000, 4) if total_tokens else None,
        "estimation_mode": "fallback",
    }


def estimate_cost(
    model: str,
    prompt: Union[str, List[Dict]],
    completion: str = "",
) -> dict:
    rust_value = run_rust_core(
        "estimate-cost",
        {"model": model, "prompt": prompt, "completion": completion},
    )
    if isinstance(rust_value, dict):
        return rust_value

    try:
        prompt_cost = float(calculate_prompt_cost(prompt, model))
        completion_cost = float(calculate_completion_cost(completion, model)) if completion else 0.0

        if isinstance(prompt, list):
            prompt_tokens = count_message_tokens(prompt, model)
        else:
            prompt_tokens = count_string_tokens(prompt, model)

        completion_tokens = count_string_tokens(completion, model) if completion else 0
        total_cost = prompt_cost + completion_cost
        total_tokens = prompt_tokens + completion_tokens

        return {
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "prompt_cost_usd": round(prompt_cost, 8),
            "completion_cost_usd": round(completion_cost, 8),
            "total_cost_usd": round(total_cost, 8),
            "cost_per_1m_tokens_usd": round(total_cost / total_tokens * 1_000_000, 4) if total_tokens else None,
            "estimation_mode": "tokencost",
        }
    except Exception:
        return _fallback_estimate(model, prompt, completion)
