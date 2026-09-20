use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git command failed: {cmd}\n{stderr}")]
    CommandFailed { cmd: String, stderr: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn checkout_pr(
    work_root: &Path,
    clone_url: &str,
    pr_number: u64,
    token: Option<&str>,
) -> Result<PathBuf, GitError> {
    std::fs::create_dir_all(work_root)?;
    let repo_dir = work_root.join(format!("pr-{pr_number}"));
    if repo_dir.exists() {
        std::fs::remove_dir_all(&repo_dir)?;
    }

    let auth_url = inject_token(clone_url, token);
    run_git(
        &[
            "clone",
            "--depth",
            "50",
            &auth_url,
            repo_dir.to_str().unwrap(),
        ],
        None,
    )?;

    let local_branch = format!("cac-pr-{pr_number}");
    let fetch_ref = format!("pull/{pr_number}/head:{local_branch}");
    run_git(&["fetch", "origin", &fetch_ref], Some(&repo_dir))?;
    run_git(&["checkout", &local_branch], Some(&repo_dir))?;
    Ok(repo_dir)
}

pub fn commit_all(repo_dir: &Path, message: &str) -> Result<bool, GitError> {
    run_git(&["add", "-A"], Some(repo_dir))?;
    let status = run_git(&["status", "--porcelain"], Some(repo_dir))?;
    if String::from_utf8_lossy(&status.stdout).trim().is_empty() {
        return Ok(false);
    }
    run_git(&["commit", "-m", message], Some(repo_dir))?;
    Ok(true)
}

pub fn push_branch(repo_dir: &Path, branch: &str, token: Option<&str>) -> Result<(), GitError> {
    let remote = run_git(&["remote", "get-url", "origin"], Some(repo_dir))?;
    let remote_url = String::from_utf8_lossy(&remote.stdout).trim().to_string();
    let auth_url = inject_token(&remote_url, token);
    run_git(&["remote", "set-url", "origin", &auth_url], Some(repo_dir))?;
    run_git(
        &["push", "origin", &format!("HEAD:refs/heads/{branch}")],
        Some(repo_dir),
    )?;
    Ok(())
}

fn run_git(args: &[&str], cwd: Option<&Path>) -> Result<Output, GitError> {
    let mut cmd = Command::new("git");
    cmd.args(args);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let output = cmd.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(GitError::CommandFailed {
            cmd: format!("git {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn inject_token(url: &str, token: Option<&str>) -> String {
    let Some(token) = token else {
        return url.to_string();
    };
    if !url.starts_with("https://") {
        return url.to_string();
    }
    let rest = url.strip_prefix("https://").unwrap_or(url);
    if rest.contains('@') {
        return url.to_string();
    }
    if rest.contains("github.com") {
        return format!("https://x-access-token:{token}@{rest}");
    }
    format!("https://{token}@{rest}")
}
