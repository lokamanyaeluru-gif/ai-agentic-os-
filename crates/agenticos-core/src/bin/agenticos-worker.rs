//! Dedicated Worker Entrypoint Binary for AgenticOS Isolation Containers (Profile 2).
//!
//! Executed inside the Bubblewrap sandbox as `/app/agenticos-worker`.
//! Communicates with the CapabilitySupervisor over inherited IPC socket descriptor (FD 3).

use agenticos_core::sandbox::worker::run_profile2_worker;
use std::env;
use std::process::exit;
use uuid::Uuid;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Check if worker was executed without args (e.g. sanity check)
    if args.len() <= 1 {
        println!("agenticos-worker binary ready");
        return;
    }

    let mut mode = String::new();
    let mut nonce_str = String::new();
    let mut host_pid: u32 = 0;
    let mut host_ticks: u64 = 0;
    let mut ipc_fd: i32 = 3;
    let mut kill_on_seccomp = true;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                if i + 1 < args.len() {
                    mode = args[i + 1].clone();
                    i += 1;
                }
            }
            "--ipc-fd" => {
                if i + 1 < args.len() {
                    ipc_fd = args[i + 1].parse().unwrap_or(3);
                    i += 1;
                }
            }
            "--nonce" => {
                if i + 1 < args.len() {
                    nonce_str = args[i + 1].clone();
                    i += 1;
                }
            }
            "--host-pid" => {
                if i + 1 < args.len() {
                    host_pid = args[i + 1].parse().unwrap_or(0);
                    i += 1;
                }
            }
            "--host-ticks" => {
                if i + 1 < args.len() {
                    host_ticks = args[i + 1].parse().unwrap_or(0);
                    i += 1;
                }
            }
            "--no-kill-seccomp" => {
                kill_on_seccomp = false;
            }
            _ => {}
        }
        i += 1;
    }

    if mode != "profile2" {
        eprintln!("Invalid worker mode: '{mode}'");
        exit(1);
    }

    let expected_nonce = match Uuid::parse_str(&nonce_str) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Invalid instance nonce: {e}");
            exit(2);
        }
    };

    // If IPC socket was passed on an inherited FD other than 3, redirect it to FD 3
    if ipc_fd != 3 {
        unsafe {
            libc::dup2(ipc_fd, 3);
            libc::close(ipc_fd);
        }
    }

    let code = run_profile2_worker(3, expected_nonce, host_pid, host_ticks, kill_on_seccomp);
    exit(code);
}
