use crate::arch;
use log::warn;
use nix::sys::mman::{MapFlags, ProtFlags};
use perf_event_open_sys as sys;
use std::{
    convert::Infallible,
    num::NonZeroUsize,
    os::fd::{FromRawFd, OwnedFd},
};
use tokio::io::unix::AsyncFd;

pub struct PerfMap {
    mmap_addr: usize,
    fd: AsyncFd<OwnedFd>,
    backtrace: bool,
}

pub struct SampleData {
    pub pid: u32,
    pub tid: u32,
    pub regs: Vec<u64>,
    pub backtrace: Option<Vec<u64>>,
}

impl PerfMap {
    pub fn new(
        r#type: u32,
        addr: u64,
        len: u64,
        pid: i32,
        buf_size: usize,
        backtrace: bool,
    ) -> anyhow::Result<Self> {
        let mut attrs = sys::bindings::perf_event_attr::default();

        attrs.set_precise_ip(2);
        attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
        attrs.type_ = sys::bindings::PERF_TYPE_BREAKPOINT;
        attrs.__bindgen_anon_1.sample_period = 1;
        attrs.__bindgen_anon_2.wakeup_events = 1;
        attrs.bp_type = r#type;
        attrs.__bindgen_anon_3.bp_addr = addr;
        attrs.__bindgen_anon_4.bp_len = len;
        attrs.sample_type = sys::bindings::PERF_SAMPLE_REGS_USER | sys::bindings::PERF_SAMPLE_TID;
        if backtrace {
            attrs.sample_type |= sys::bindings::PERF_SAMPLE_CALLCHAIN;
            attrs.set_exclude_callchain_kernel(1);
            attrs.set_exclude_callchain_kernel(0);
        }
        attrs.sample_regs_user = arch::SAMPLE_REGS_USER;

        let perf_fd = unsafe {
            OwnedFd::from_raw_fd(nix::Error::result(sys::perf_event_open(
                &mut attrs,
                pid,
                -1,
                -1,
                (sys::bindings::PERF_FLAG_FD_CLOEXEC) as u64,
            ))?)
        };
        let mmap_addr = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new((1 + (1 << buf_size)) * 4096).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &perf_fd,
                0,
            )
        }?.as_ptr() as usize;
        let mmap_page_metadata = unsafe {
            (mmap_addr as *mut sys::bindings::perf_event_mmap_page)
                .as_mut()
                .unwrap()
        };
        if mmap_page_metadata.compat_version != 0 {
            anyhow::bail!("unsupported mmap_page version");
        }
        Ok(Self {
            mmap_addr: mmap_addr as usize,
            fd: AsyncFd::new(perf_fd)?,
            backtrace,
        })
    }

    pub async fn events<F: FnMut(SampleData)>(&self, mut handle: F) -> anyhow::Result<Infallible> {
        let mmap_page_metadata = unsafe {
            (self.mmap_addr as *mut sys::bindings::perf_event_mmap_page)
                .as_mut()
                .unwrap()
        };
        let data_addr = self.mmap_addr + mmap_page_metadata.data_offset as usize;
        let data_size = mmap_page_metadata.data_size as usize;
        let mut read_data_size = 0u64;
        loop {
            let guard = self.fd.readable().await?;
            while mmap_page_metadata.data_head != read_data_size {
                let get_addr =
                    |offset: usize| data_addr + ((read_data_size as usize + offset) % data_size);
                let data_header = unsafe {
                    (get_addr(0) as *const sys::bindings::perf_event_header)
                        .as_ref()
                        .unwrap()
                };
                let mut offset = std::mem::size_of::<sys::bindings::perf_event_header>();
                if data_header.type_ == sys::bindings::PERF_RECORD_SAMPLE {
                    let pid = unsafe { *(get_addr(offset) as *const u32) };
                    offset += 4;
                    let tid = unsafe { *(get_addr(offset) as *const u32) };
                    offset += 4;
                    let backtrace = self.backtrace.then(|| {
                        let backtrace_size = unsafe { *(get_addr(offset) as *const u64) };
                        offset += 8;
                        (0..backtrace_size)
                            .map(|_| {
                                let addr = unsafe { *(get_addr(offset) as *const u64) };
                                offset += 8;
                                addr
                            })
                            .collect()
                    });
                    offset += 8;
                    let mut regs = vec![0u64; arch::regs_count()];
                    for reg in regs.iter_mut().take(arch::regs_count()) {
                        *reg = unsafe { *(get_addr(offset) as *const u64) };
                        offset += 8;
                    }
                    handle(SampleData {
                        pid,
                        tid,
                        regs,
                        backtrace,
                    });
                } else if data_header.type_ == sys::bindings::PERF_RECORD_LOST {
                    let lost = unsafe { *(get_addr(offset) as *const u64) };
                    warn!("Lost {} events", lost);
                } else {
                    warn!("Unknown type");
                }
                read_data_size += data_header.size as u64;
                mmap_page_metadata.data_tail = read_data_size;
            }
            drop(guard);
        }
    }
}
