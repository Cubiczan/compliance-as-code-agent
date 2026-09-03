use serde_json::Value;
use std::env;
use std::io::{self, Read};

use te_core::{
    canonical_usage, dashboard_summary, estimate_cost, eps_impact, forecast, monthly_snapshot,
    monthly_trends, price_usage, session_summary, workflow_economics,
};

fn read_input() -> Result<Value, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("failed to read stdin: {err}"))?;
    if input.trim().is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_str(&input).map_err(|err| format!("invalid JSON input: {err}"))
    }
}

fn main() {
    let command = match env::args().nth(1) {
        Some(command) => command,
        None => {
            eprintln!("missing command");
            std::process::exit(2);
        }
    };

    let input = match read_input() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let output = match command.as_str() {
        "canonical-usage" => canonical_usage(
            input.get("provider").and_then(Value::as_str).unwrap_or("canonical"),
            input.get("usage").unwrap_or(&Value::Null),
        ),
        "price-usage" => price_usage(
            input.get("model").and_then(Value::as_str).unwrap_or(""),
            input.get("usage").unwrap_or(&Value::Null),
        ),
        "estimate-cost" => estimate_cost(
            input.get("model").and_then(Value::as_str).unwrap_or(""),
            input.get("prompt").unwrap_or(&Value::Null),
            input.get("completion").and_then(Value::as_str).unwrap_or(""),
        ),
        "session-summary" => session_summary(
            input.get("session_id").and_then(Value::as_str).unwrap_or(""),
            input.get("records").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
        ),
        "workflow-economics" => workflow_economics(
            input.get("workflows").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
            input.get("usage_events").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
        ),
        "dashboard-summary" => dashboard_summary(
            input.get("config").unwrap_or(&Value::Null),
            input.get("mtd_events").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
            input.get("ytd_events").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
            input.get("workflow_economics").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
            input.get("benchmarks").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
        ),
        "forecast" => forecast(
            input.get("trends").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
            input.get("months_ahead").and_then(Value::as_i64).unwrap_or(6),
        ),
        "roi-scenario" => {
            let prompt_tokens = input.get("avg_prompt_tokens").and_then(Value::as_i64).unwrap_or(2000);
            let completion_tokens = input.get("avg_completion_tokens").and_then(Value::as_i64).unwrap_or(800);
            let prompt = Value::String("x".repeat(prompt_tokens.max(0) as usize));
            let completion = "x".repeat(completion_tokens.max(0) as usize);
            let per_run = estimate_cost(
                input.get("model").and_then(Value::as_str).unwrap_or(""),
                &prompt,
                &completion,
            );
            let annual_runs = input.get("annual_runs").and_then(Value::as_f64).unwrap_or(1000.0);
            let success_rate = input.get("success_rate").and_then(Value::as_f64).unwrap_or(0.85);
            let successful_runs = annual_runs * success_rate;
            let annual_token_cost = per_run.get("total_cost_usd").and_then(Value::as_f64).unwrap_or(0.0) * annual_runs * 1.85;
            let labor_value = input.get("avg_hours_saved").and_then(Value::as_f64).unwrap_or(0.0)
                * input.get("hourly_cost_usd").and_then(Value::as_f64).unwrap_or(150.0)
                * successful_runs;
            let revenue_value = input.get("avg_revenue_lift_usd").and_then(Value::as_f64).unwrap_or(0.0) * successful_runs;
            let manual_savings = input.get("manual_baseline_cost_usd").and_then(Value::as_f64).unwrap_or(0.0) * successful_runs;
            let annual_value = labor_value + revenue_value + manual_savings;
            let net_value = annual_value - annual_token_cost;
            let roi = if annual_token_cost > 0.0 { annual_value / annual_token_cost } else { 0.0 };
            let cost_per_task = if successful_runs > 0.0 { annual_token_cost / successful_runs } else { 0.0 };
            let payback = if net_value > 0.0 && annual_token_cost > 0.0 { Some((annual_token_cost / (net_value / 12.0)).round()) } else { None };
            let rec = if roi >= 5.0 {
                "Strategic investment — scale with governance and model routing."
            } else if roi >= 2.0 {
                "Viable — optimize with caching and medium reasoning effort."
            } else if roi >= 1.0 {
                "Marginal — require outcome attribution before expanding."
            } else {
                "Underwater — pause scaling; fix success rate or switch models."
            };

            serde_json::json!({
                "annual_token_cost_usd": (annual_token_cost * 100.0).round() / 100.0,
                "annual_value_usd": (annual_value * 100.0).round() / 100.0,
                "annual_net_value_usd": (net_value * 100.0).round() / 100.0,
                "roi_multiple": (roi * 100.0).round() / 100.0,
                "payback_months": payback,
                "cost_per_successful_task_usd": (cost_per_task * 10_000.0).round() / 10_000.0,
                "recommendation": rec,
            })
        }
        "monthly-snapshot" => monthly_snapshot(
            input.get("events").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
        ),
        "monthly-trends" => monthly_trends(
            input.get("snapshots").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
        ),
        "eps-impact" => eps_impact(
            input.get("config").unwrap_or(&Value::Null),
            input.get("net_value_usd").and_then(Value::as_f64).unwrap_or(0.0),
        ),
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(2);
        }
    };

    if serde_json::to_writer(io::stdout(), &output).is_err() {
        std::process::exit(1);
    }
}
