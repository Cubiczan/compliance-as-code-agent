use serde_json::{json, Map, Value};
use std::collections::HashMap;

fn num(value: &Value, key: &str) -> f64 {
    value.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

fn int(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn round(value: f64, digits: i32) -> f64 {
    let factor = 10_f64.powi(digits);
    (value * factor).round() / factor
}

#[derive(Clone, Copy)]
struct ModelCosts {
    input: f64,
    output: f64,
    cache_write: f64,
    cache_read: f64,
    web_search: f64,
}

fn model_costs(model: &str) -> (ModelCosts, bool) {
    let key = model.trim().to_lowercase();
    let costs = if key == "gpt-4o-mini" || key == "gpt-4.1-mini" {
        ModelCosts {
            input: 0.15,
            output: 0.60,
            cache_write: 0.19,
            cache_read: 0.015,
            web_search: 0.01,
        }
    } else if key == "gpt-4o" || key == "gpt-4.1" {
        ModelCosts {
            input: 2.5,
            output: 10.0,
            cache_write: 3.125,
            cache_read: 0.25,
            web_search: 0.01,
        }
    } else if key.starts_with("claude-3-5-sonnet") || key == "claude-sonnet-4-20250514" {
        ModelCosts {
            input: 3.0,
            output: 15.0,
            cache_write: 3.75,
            cache_read: 0.30,
            web_search: 0.01,
        }
    } else if key == "claude-opus-4-20250514" {
        ModelCosts {
            input: 15.0,
            output: 75.0,
            cache_write: 18.75,
            cache_read: 1.5,
            web_search: 0.01,
        }
    } else if key == "o1-mini" {
        ModelCosts {
            input: 1.1,
            output: 4.4,
            cache_write: 1.375,
            cache_read: 0.11,
            web_search: 0.01,
        }
    } else {
        ModelCosts {
            input: 3.0,
            output: 15.0,
            cache_write: 3.75,
            cache_read: 0.30,
            web_search: 0.01,
        }
    };

    let known = matches!(
        key.as_str(),
        "gpt-4o-mini"
            | "gpt-4o"
            | "gpt-4.1"
            | "gpt-4.1-mini"
            | "claude-3-5-sonnet-20241022"
            | "claude-3-5-sonnet-latest"
            | "claude-sonnet-4-20250514"
            | "claude-opus-4-20250514"
            | "o1-mini"
    );

    (costs, !known)
}

fn approx_tokens(text: &str) -> i64 {
    std::cmp::max(1, (text.chars().count() / 4) as i64)
}

fn prompt_to_text(prompt: &Value) -> String {
    match prompt {
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.get("content")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| item.to_string())
            })
            .collect::<Vec<_>>()
            .join(" "),
        _ => prompt.to_string(),
    }
}

pub fn canonical_usage(provider: &str, usage: &Value) -> Value {
    let provider_key = provider.trim().to_lowercase();
    let canonical =
        if provider_key == "openai" || provider_key == "openrouter" || provider_key == "azure" {
            let prompt_tokens = int(usage, "prompt_tokens");
            let cached = usage
                .get("prompt_tokens_details")
                .and_then(Value::as_object)
                .and_then(|d| d.get("cached_tokens"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            json!({
                "input_tokens": std::cmp::max(0, prompt_tokens - cached),
                "output_tokens": int(usage, "completion_tokens"),
                "cache_read_input_tokens": cached,
                "cache_creation_input_tokens": 0,
                "web_search_requests": 0,
            })
        } else if provider_key == "anthropic" || provider_key == "claude" {
            json!({
                "input_tokens": int(usage, "input_tokens"),
                "output_tokens": int(usage, "output_tokens"),
                "cache_read_input_tokens": int(usage, "cache_read_input_tokens"),
                "cache_creation_input_tokens": int(usage, "cache_creation_input_tokens"),
                "web_search_requests": 0,
            })
        } else if provider_key == "canonical" {
            json!({
                "input_tokens": int(usage, "input_tokens"),
                "output_tokens": int(usage, "output_tokens"),
                "cache_read_input_tokens": int(usage, "cache_read_input_tokens"),
                "cache_creation_input_tokens": int(usage, "cache_creation_input_tokens"),
                "web_search_requests": int(usage, "web_search_requests"),
            })
        } else if usage.get("prompt_tokens").is_some() || usage.get("completion_tokens").is_some() {
            let prompt_tokens = int(usage, "prompt_tokens");
            let cached = usage
                .get("prompt_tokens_details")
                .and_then(Value::as_object)
                .and_then(|d| d.get("cached_tokens"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            json!({
                "input_tokens": std::cmp::max(0, prompt_tokens - cached),
                "output_tokens": int(usage, "completion_tokens"),
                "cache_read_input_tokens": cached,
                "cache_creation_input_tokens": 0,
                "web_search_requests": 0,
            })
        } else {
            json!({
                "input_tokens": int(usage, "input_tokens"),
                "output_tokens": int(usage, "output_tokens"),
                "cache_read_input_tokens": int(usage, "cache_read_input_tokens"),
                "cache_creation_input_tokens": int(usage, "cache_creation_input_tokens"),
                "web_search_requests": int(usage, "web_search_requests"),
            })
        };
    canonical
}

pub fn price_usage(model: &str, usage: &Value) -> Value {
    let canonical = canonical_usage("canonical", usage);
    let (costs, unknown_model) = model_costs(model);

    let input_tokens = int(&canonical, "input_tokens") as f64;
    let output_tokens = int(&canonical, "output_tokens") as f64;
    let cache_read_tokens = int(&canonical, "cache_read_input_tokens") as f64;
    let cache_write_tokens = int(&canonical, "cache_creation_input_tokens") as f64;
    let web_search = int(&canonical, "web_search_requests") as f64;

    let input_cost = input_tokens / 1_000_000.0 * costs.input;
    let output_cost = output_tokens / 1_000_000.0 * costs.output;
    let cache_read_cost = cache_read_tokens / 1_000_000.0 * costs.cache_read;
    let cache_write_cost = cache_write_tokens / 1_000_000.0 * costs.cache_write;
    let web_cost = web_search * costs.web_search;
    let total = input_cost + output_cost + cache_read_cost + cache_write_cost + web_cost;

    json!({
        "model": model,
        "usage": canonical,
        "input_cost_usd": round(input_cost, 8),
        "output_cost_usd": round(output_cost, 8),
        "cache_read_cost_usd": round(cache_read_cost, 8),
        "cache_write_cost_usd": round(cache_write_cost, 8),
        "web_search_cost_usd": round(web_cost, 8),
        "total_cost_usd": round(total, 8),
        "pricing_tier": "canonical",
        "unknown_model": unknown_model,
    })
}

pub fn estimate_cost(model: &str, prompt: &Value, completion: &str) -> Value {
    let prompt_text = prompt_to_text(prompt);
    let prompt_tokens = approx_tokens(&prompt_text);
    let completion_tokens = if completion.is_empty() {
        0
    } else {
        approx_tokens(completion)
    };
    let (costs, _) = model_costs(model);

    let prompt_cost = prompt_tokens as f64 * costs.input / 1_000_000.0;
    let completion_cost = completion_tokens as f64 * costs.output / 1_000_000.0;
    let total_cost = prompt_cost + completion_cost;
    let total_tokens = prompt_tokens + completion_tokens;

    json!({
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "prompt_cost_usd": round(prompt_cost, 8),
        "completion_cost_usd": round(completion_cost, 8),
        "total_cost_usd": round(total_cost, 8),
        "cost_per_1m_tokens_usd": if total_tokens > 0 { Some(round(total_cost / total_tokens as f64 * 1_000_000.0, 4)) } else { None },
        "estimation_mode": "rust",
    })
}

pub fn session_summary(session_id: &str, rows: &[Value]) -> Value {
    if rows.is_empty() {
        return json!({
            "session_id": session_id,
            "call_count": 0,
            "total_cost_usd": 0.0,
            "total_tokens": 0,
            "by_model": {},
            "by_agent": {},
            "records": [],
        });
    }

    let mut by_model: HashMap<String, Map<String, Value>> = HashMap::new();
    let mut by_agent: HashMap<String, f64> = HashMap::new();
    let mut total_cost = 0.0;
    let mut total_tokens = 0_i64;

    for row in rows {
        let model = text(row, "model");
        let bucket = by_model.entry(model.clone()).or_insert_with(|| {
            Map::from_iter([
                ("input_tokens".to_string(), json!(0)),
                ("output_tokens".to_string(), json!(0)),
                ("cache_read_input_tokens".to_string(), json!(0)),
                ("cache_creation_input_tokens".to_string(), json!(0)),
                ("cost_usd".to_string(), json!(0.0)),
                ("calls".to_string(), json!(0)),
            ])
        });

        let input_tokens = int(row, "input_tokens");
        let output_tokens = int(row, "output_tokens");
        let cache_read = int(row, "cache_read_input_tokens");
        let cache_write = int(row, "cache_creation_input_tokens");
        let row_cost = num(row, "total_cost_usd");

        bucket.insert(
            "input_tokens".to_string(),
            json!(
                bucket
                    .get("input_tokens")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    + input_tokens
            ),
        );
        bucket.insert(
            "output_tokens".to_string(),
            json!(
                bucket
                    .get("output_tokens")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    + output_tokens
            ),
        );
        bucket.insert(
            "cache_read_input_tokens".to_string(),
            json!(
                bucket
                    .get("cache_read_input_tokens")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    + cache_read
            ),
        );
        bucket.insert(
            "cache_creation_input_tokens".to_string(),
            json!(
                bucket
                    .get("cache_creation_input_tokens")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    + cache_write
            ),
        );
        bucket.insert(
            "cost_usd".to_string(),
            json!(
                bucket
                    .get("cost_usd")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0)
                    + row_cost
            ),
        );
        bucket.insert(
            "calls".to_string(),
            json!(bucket.get("calls").and_then(Value::as_i64).unwrap_or(0) + 1),
        );

        if let Some(agent_id) = row.get("agent_id").and_then(Value::as_str) {
            *by_agent.entry(agent_id.to_string()).or_insert(0.0) += row_cost;
        }

        total_cost += row_cost;
        total_tokens += input_tokens + output_tokens + cache_read + cache_write;
    }

    let source = rows[0].get("source").and_then(Value::as_str).unwrap_or("");
    let workflow_id = rows[0].get("workflow_id").cloned().unwrap_or(Value::Null);
    let first = rows[0].get("recorded_at").cloned().unwrap_or(Value::Null);
    let last = rows
        .last()
        .and_then(|row| row.get("recorded_at").cloned())
        .unwrap_or(Value::Null);

    json!({
        "session_id": session_id,
        "source": source,
        "workflow_id": workflow_id,
        "call_count": rows.len(),
        "total_cost_usd": round(total_cost, 8),
        "total_tokens": total_tokens,
        "by_model": by_model,
        "by_agent": by_agent.into_iter().map(|(k, v)| (k, json!(round(v, 8)))).collect::<Map<String, Value>>(),
        "first_recorded_at": first,
        "last_recorded_at": last,
    })
}

fn aggregate_events(events: &[Value]) -> (f64, f64, i64, i64, f64, f64) {
    let spend: f64 = events.iter().map(|e| num(e, "total_cost_usd")).sum();
    let lift: f64 = events
        .iter()
        .filter(|e| {
            e.get("successful")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .map(|e| num(e, "revenue_lift_usd"))
        .sum();
    let successful = events
        .iter()
        .filter(|e| {
            e.get("successful")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count() as i64;
    let failed = events.len() as i64 - successful;
    let cost_per_task = if successful > 0 {
        spend / successful as f64
    } else {
        0.0
    };
    let roi = if spend > 0.0 { lift / spend } else { 0.0 };
    (spend, lift, successful, failed, cost_per_task, roi)
}

pub fn eps_impact(config: &Value, net_value_usd: f64) -> Value {
    let shares = num(config, "shares_outstanding_millions") * 1_000_000.0;
    let eps = if shares > 0.0 {
        net_value_usd / shares
    } else {
        0.0
    };
    let tech_load = num(config, "annual_tech_investment_billions") * 1_000_000_000.0;
    let eps_at_risk_pct = if shares > 0.0 && num(config, "earnings_per_share") > 0.0 {
        tech_load / shares / num(config, "earnings_per_share") * 100.0
    } else {
        0.0
    };
    json!({
        "eps_impact_per_share_usd": round(eps, 4),
        "eps_at_risk_pct": round(eps_at_risk_pct, 2),
    })
}

pub fn workflow_economics(workflows: &[Value], usage_events: &[Value]) -> Value {
    let mut results = Vec::new();

    for wf in workflows {
        let wf_id = wf.get("id").cloned().unwrap_or(Value::Null);
        let events: Vec<Value> = usage_events
            .iter()
            .filter(|e| e.get("workflow_id") == Some(&wf_id))
            .cloned()
            .collect();
        let (spend, lift, successful, failed, cost_per_task, roi) = aggregate_events(&events);

        let benchmark_roi = wf.get("benchmark_roi_median").and_then(Value::as_f64);
        let vs_benchmark = benchmark_roi.and_then(|bench| {
            if bench > 0.0 {
                Some(round((roi / bench - 1.0) * 100.0, 1))
            } else {
                None
            }
        });
        let status = if roi >= 3.0 {
            "high_leverage"
        } else if roi >= 1.0 {
            "viable"
        } else if spend > 0.0 {
            "underwater"
        } else {
            "uninstrumented"
        };

        results.push(json!({
            "workflow": wf,
            "total_spend_usd": round(spend, 2),
            "total_revenue_lift_usd": round(lift, 2),
            "successful_runs": successful,
            "failed_runs": failed,
            "cost_per_successful_task_usd": round(cost_per_task, 4),
            "roi_multiple": round(roi, 2),
            "vs_benchmark_roi": vs_benchmark,
            "status": status,
        }));
    }

    results.sort_by(|a, b| {
        let ar = a.get("roi_multiple").and_then(Value::as_f64).unwrap_or(0.0);
        let br = b.get("roi_multiple").and_then(Value::as_f64).unwrap_or(0.0);
        br.partial_cmp(&ar).unwrap_or(std::cmp::Ordering::Equal)
    });

    Value::Array(results)
}

pub fn dashboard_summary(
    config: &Value,
    mtd_events: &[Value],
    ytd_events: &[Value],
    workflow_economics: &[Value],
    benchmarks: &[Value],
) -> Value {
    let (mtd_spend, mtd_lift, mtd_success, mtd_failed, mtd_cost_per_task, mtd_roi) =
        aggregate_events(mtd_events);
    let (ytd_spend, _, _, _, _, _) = aggregate_events(ytd_events);
    let net_value = mtd_lift - mtd_spend;
    let eps = eps_impact(config, net_value);
    let months_elapsed = num(config, "month").max(1.0);
    let projected_annual = (ytd_spend / months_elapsed) * 12.0 / 1_000_000.0;
    let budget_util = if num(config, "ai_compute_budget_millions") > 0.0 {
        mtd_spend / (num(config, "ai_compute_budget_millions") * 1_000_000.0 / 12.0) * 100.0
    } else {
        0.0
    };
    let underwater = workflow_economics
        .iter()
        .filter(|w| w.get("roi_multiple").and_then(Value::as_f64).unwrap_or(0.0) < 1.0)
        .count() as i64;
    let high_leverage = workflow_economics
        .iter()
        .filter(|w| w.get("roi_multiple").and_then(Value::as_f64).unwrap_or(0.0) >= 3.0)
        .count() as i64;
    let benchmark_median = {
        let items: Vec<f64> = benchmarks
            .iter()
            .take(8)
            .filter_map(|b| b.get("median_roi").and_then(Value::as_f64))
            .collect();
        if items.is_empty() {
            0.0
        } else {
            items.iter().sum::<f64>() / items.len() as f64
        }
    };
    let success_total = mtd_success + mtd_failed;
    let success_rate = if success_total > 0 {
        mtd_success as f64 / success_total as f64 * 100.0
    } else {
        0.0
    };

    json!({
        "total_spend_mtd_usd": round(mtd_spend, 2),
        "total_spend_ytd_usd": round(ytd_spend, 2),
        "portfolio_roi": round(mtd_roi, 2),
        "cost_per_successful_task_usd": round(mtd_cost_per_task, 4),
        "successful_tasks_mtd": mtd_success,
        "failed_tasks_mtd": mtd_failed,
        "success_rate_pct": round(success_rate, 1),
        "ai_budget_utilization_pct": round(budget_util.min(999.0), 1),
        "revenue_lift_mtd_usd": round(mtd_lift, 2),
        "net_value_mtd_usd": round(net_value, 2),
        "eps_impact_per_share_usd": eps.get("eps_impact_per_share_usd").and_then(Value::as_f64).unwrap_or(0.0),
        "eps_at_risk_pct": eps.get("eps_at_risk_pct").and_then(Value::as_f64).unwrap_or(0.0),
        "projected_annual_spend_millions": round(projected_annual, 2),
        "benchmark_median_roi": round(benchmark_median, 2),
        "workflows_underwater": underwater,
        "workflows_high_leverage": high_leverage,
    })
}

pub fn forecast(trends: &[Value], months_ahead: i64) -> Value {
    if trends.len() < 2 {
        return Value::Array(vec![]);
    }

    let recent = if trends.len() >= 3 {
        &trends[trends.len() - 3..]
    } else {
        trends
    };
    let avg_spend = recent
        .iter()
        .map(|t| num(t, "total_spend_usd"))
        .sum::<f64>()
        / recent.len() as f64;
    let avg_roi = recent.iter().map(|t| num(t, "portfolio_roi")).sum::<f64>() / recent.len() as f64;
    let growth = 1.08_f64;

    let last_month = text(trends.last().unwrap(), "month");
    let (mut year, mut month) = last_month
        .split_once('-')
        .and_then(|(y, m)| Some((y.parse::<i32>().ok()?, m.parse::<i32>().ok()?)))
        .unwrap_or((2025, 1));

    let mut projected = avg_spend;
    let mut forecasts = Vec::new();
    for _ in 0..months_ahead.max(0) {
        month += 1;
        if month > 12 {
            month = 1;
            year += 1;
        }
        projected *= growth;
        let label = format!("{year:04}-{month:02}");
        forecasts.push(json!({
            "month": label,
            "projected_spend_usd": round(projected, 2),
            "projected_roi": round(avg_roi * 0.98, 2),
            "confidence_low_usd": round(projected * 0.85, 2),
            "confidence_high_usd": round(projected * 1.25, 2),
        }));
    }

    Value::Array(forecasts)
}

pub fn monthly_snapshot(events: &[Value]) -> Value {
    if events.is_empty() {
        return json!({
            "total_spend_usd": 0.0,
            "total_revenue_lift_usd": 0.0,
            "successful_tasks": 0,
            "failed_tasks": 0,
            "cost_per_successful_task_usd": 0.0,
            "portfolio_roi": 0.0,
            "token_volume_millions": 0.0,
        });
    }

    let (spend, lift, successful, failed, cost_per_task, roi) = aggregate_events(events);
    let tokens = events
        .iter()
        .map(|e| int(e, "prompt_tokens") + int(e, "completion_tokens"))
        .sum::<i64>() as f64
        / 1_000_000.0;

    json!({
        "total_spend_usd": round(spend, 2),
        "total_revenue_lift_usd": round(lift, 2),
        "successful_tasks": successful,
        "failed_tasks": failed,
        "cost_per_successful_task_usd": round(cost_per_task, 4),
        "portfolio_roi": round(roi, 2),
        "token_volume_millions": round(tokens, 3),
    })
}

pub fn monthly_trends(snapshots: &[Value]) -> Value {
    Value::Array(
        snapshots
            .iter()
            .map(|s| {
                json!({
                    "month": text(s, "month"),
                    "total_spend_usd": num(s, "total_spend_usd"),
                    "total_revenue_lift_usd": num(s, "total_revenue_lift_usd"),
                    "portfolio_roi": num(s, "portfolio_roi"),
                    "cost_per_successful_task_usd": num(s, "cost_per_successful_task_usd"),
                    "successful_tasks": int(s, "successful_tasks"),
                    "token_volume_millions": num(s, "token_volume_millions"),
                })
            })
            .collect(),
    )
}
