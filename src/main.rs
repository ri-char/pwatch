use clap::Parser;
use colored::Colorize;
use nix::poll::{PollFd, PollFlags};
use nix::sys::mman::{MapFlags, ProtFlags};
use perf_event_open_sys as sys;
use std::{
    num::NonZeroUsize,
    os::fd::{FromRawFd, OwnedFd},
};
mod arch;

#[derive(Parser)]
struct Args {
    #[arg(short, default_value = "0")]
    /// buffer size, in power of 2. For example, 2 means 2^2 pages = 4 * 4096 bytes.
    buf_size: usize,
    /// target pid
    pid: u32,
    /// watchpoint type, can be read(r), write(w), readwrite(rw) or execve(e).
    /// if it is one of r, w, rw, the watchpoint length is needed. Valid length is 1, 2, 4, 8.
    /// For example, r4 means a read watchpoint with length 4 and rw1 means a readwrite watchpoint with length 1.
    r#type: String,
    /// watchpoint address, in hex format. 0x prefix is optional.
    addr: String,
}

fn parse_len(s: &str) -> Option<u32> {
    match s {
        "1" => Some(sys::bindings::HW_BREAKPOINT_LEN_1),
        "2" => Some(sys::bindings::HW_BREAKPOINT_LEN_2),
        "4" => Some(sys::bindings::HW_BREAKPOINT_LEN_4),
        "8" => Some(sys::bindings::HW_BREAKPOINT_LEN_8),
        _ => None,
    }
}

fn parse_watchpoint_type(s: &str) -> Option<(u32, u32)> {
    if let Some(s) = s.strip_prefix("rw") {
        let len = parse_len(s)?;
        Some((sys::bindings::HW_BREAKPOINT_RW, len))
    } else if let Some(s) = s.strip_prefix("r") {
        let len = parse_len(s)?;
        Some((sys::bindings::HW_BREAKPOINT_R, len))
    } else if let Some(s) = s.strip_prefix("w") {
        let len = parse_len(s)?;
        Some((sys::bindings::HW_BREAKPOINT_W, len))
    } else if s == "e" {
        Some((
            sys::bindings::HW_BREAKPOINT_X,
            std::mem::size_of::<nix::libc::c_long>() as u32,
        ))
    } else {
        None
    }
}

fn parse_addr(s: &str) -> Option<u64> {
    if s.starts_with("0x") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else {
        u64::from_str_radix(s, 16).ok()
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let (ty, bp_len) = parse_watchpoint_type(&args.r#type)
        .ok_or_else(|| anyhow::anyhow!(format!("invalid watchpoint type: {}", args.r#type)))?;
    let addr = parse_addr(&args.addr)
        .ok_or_else(|| anyhow::anyhow!(format!("invalid address: {}", args.addr)))?;

    let mut attrs = sys::bindings::perf_event_attr::default();

    // Populate the fields we need.
    attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
    attrs.type_ = sys::bindings::PERF_TYPE_BREAKPOINT;
    attrs.__bindgen_anon_1.sample_period = 1;
    attrs.__bindgen_anon_2.wakeup_events = 1;
    attrs.bp_type = ty;
    attrs.__bindgen_anon_3.bp_addr = addr;
    attrs.__bindgen_anon_4.bp_len = bp_len as u64;
    attrs.set_precise_ip(2);
    attrs.sample_type = sys::bindings::PERF_SAMPLE_REGS_USER;
    attrs.sample_regs_user = arch::SAMPLE_REGS_USER;

    let perf_fd = unsafe {
        OwnedFd::from_raw_fd(nix::Error::result(sys::perf_event_open(
            &mut attrs,
            args.pid as i32,
            -1,
            -1,
            (sys::bindings::PERF_FLAG_FD_CLOEXEC) as u64,
        ))?)
    };
    let mmap_addr = unsafe {
        nix::sys::mman::mmap(
            None,
            NonZeroUsize::new((1 + (1 << args.buf_size)) * 4096).unwrap(),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
            Some(&perf_fd),
            0,
        )
    }?;
    let mmap_page_metadata = unsafe {
        (mmap_addr as *mut sys::bindings::perf_event_mmap_page)
            .as_mut()
            .unwrap()
    };
    if mmap_page_metadata.compat_version != 0 {
        anyhow::bail!("unsupported mmap_page version");
    }
    let data_addr = unsafe { mmap_addr.add(mmap_page_metadata.data_offset as usize) };
    let data_size = mmap_page_metadata.data_size as usize;
    let mut read_data_size = 0u64;
    loop {
        while mmap_page_metadata.data_head != read_data_size {
            let data_header = unsafe {
                (data_addr.add(read_data_size as usize % data_size)
                    as *const sys::bindings::perf_event_header)
                    .as_ref()
                    .unwrap()
            };
            if data_header.type_ == sys::bindings::PERF_RECORD_SAMPLE {
                let abi = unsafe {
                    *(data_addr.add(
                        (read_data_size as usize
                            + std::mem::size_of::<sys::bindings::perf_event_header>())
                            % data_size,
                    ) as *const u64)
                };
                let regs_len = data_header.size as usize
                    - std::mem::size_of::<sys::bindings::perf_event_header>()
                    - std::mem::size_of::<u64>();
                let regs_len = regs_len / 8;
                let mut regs = vec![0u64; regs_len];
                for i in 0..regs_len {
                    regs[i] = unsafe {
                        *(data_addr.add(
                            (read_data_size as usize
                                + std::mem::size_of::<sys::bindings::perf_event_header>()
                                + std::mem::size_of::<u64>()
                                + i * 8)
                                % data_size,
                        ) as *const u64)
                    };
                }
                handle_event(abi, regs);
            } else if data_header.type_ == sys::bindings::PERF_RECORD_LOST {
                let lost = unsafe {
                    *(data_addr.add(
                        (read_data_size as usize
                            + std::mem::size_of::<sys::bindings::perf_event_header>())
                            % data_size,
                    ) as *const u64)
                };
                println!("Lost {} events", lost);
            } else {
                println!("unknown type");
            }
            read_data_size += data_header.size as u64;
            mmap_page_metadata.data_tail = read_data_size;
        }
        let pollfd = PollFd::new(&perf_fd, PollFlags::POLLIN);
        nix::poll::poll(&mut [pollfd], 0)?;
    }
}

fn handle_event(_abi: u64, regs: Vec<u64>) {
    println!("-------");
    for (i, reg) in regs.iter().enumerate() {
        print!("{:>5}: 0x{:016x} ", arch::id_to_str(i).bold().blue(), reg);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    if regs.len() % 4 != 0 {
        println!();
    }
}
