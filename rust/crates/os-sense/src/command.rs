use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LimitedCommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

pub(crate) fn run_limited_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<LimitedCommandOutput, std::io::Error> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .map(|pipe| read_limited(pipe, stdout_limit));
    let stderr = child
        .stderr
        .take()
        .map(|pipe| read_limited(pipe, stderr_limit));
    let started = Instant::now();
    let mut timed_out = false;
    let success = loop {
        if let Some(status) = child.try_wait()? {
            break status.success();
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break false;
        }
        thread::sleep(Duration::from_millis(10));
    };

    let (stdout_bytes, stdout_truncated) = stdout
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    let (stderr_bytes, stderr_truncated) = stderr
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();

    Ok(LimitedCommandOutput {
        success,
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        timed_out,
        stdout_truncated,
        stderr_truncated,
    })
}

fn read_limited<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
) -> thread::JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let mut out = Vec::new();
        let mut truncated = false;
        let mut buf = [0_u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => {
                    let remaining = limit.saturating_sub(out.len());
                    if remaining > 0 {
                        out.extend_from_slice(&buf[..read.min(remaining)]);
                    }
                    if read > remaining {
                        truncated = true;
                    }
                }
                Err(_) => break,
            }
        }
        (out, truncated)
    })
}
