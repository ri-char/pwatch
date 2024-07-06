use nix::libc;
use std::sync::atomic::Ordering::SeqCst;
use std::{sync::atomic::AtomicU64, thread};

const COUNTER: AtomicU64 = AtomicU64::new(0);

fn main() {
    println!("pid: {}", std::process::id());
    let builder = thread::Builder::new();
    builder
        .spawn(|| {
            let tid = unsafe { libc::gettid() };
            loop {
                COUNTER.store(COUNTER.load(SeqCst) + 1, SeqCst);
                println!(
                    "[{}] ptr: {:p} {}",
                    tid,
                    COUNTER.as_ptr(),
                    COUNTER.load(SeqCst)
                );
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        })
        .unwrap();
    let tid = unsafe { libc::gettid() };
    loop {
        COUNTER.store(COUNTER.load(SeqCst) + 1, SeqCst);
        println!(
            "[{}] ptr: {:p} {}",
            tid,
            COUNTER.as_ptr(),
            COUNTER.load(SeqCst)
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
