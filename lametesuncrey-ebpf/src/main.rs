#![no_std]
#![no_main]

use aya_ebpf::bindings::{BPF_ANY, BPF_RB_FORCE_WAKEUP, BPF_RB_NO_WAKEUP};
use aya_ebpf::helpers::{bpf_probe_read_kernel, generated::bpf_ktime_get_ns};
use aya_ebpf::macros::{kprobe, map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::{
    maps::HashMap,
    programs::{ProbeContext, TracePointContext},
};
use lametesuncrey_ebpf::bindings::vmlinux::sk_buff;
use network_types::ip::IpProto;
use network_types::{ip::Ipv4Hdr, udp::UdpHdr};

#[map(name = "TX_TIME_MAP")]
static TX_TIME_MAP: HashMap<u64, u64> = HashMap::with_max_entries(65536, 0);
#[map(name = "LATENCY_ARRAY")]
static LATENCY_ARRAY: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

static BATCH_SIZE: u64 = 5000;
static CLIENT_PORT: u16 = 14000;

static mut EVENT_COUNTER: u64 = 0;

#[tracepoint]
pub fn trace_netif_receive_skb(ctx: TracePointContext) -> u32 {
    match try_trace_netif_receive_skb(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn try_trace_netif_receive_skb(ctx: TracePointContext) -> Result<u32, u32> {
    let skb_addr: *const sk_buff = unsafe { ctx.read_at(8).map_err(|c| c as u32)? };
    let data_len =
        unsafe { bpf_probe_read_kernel(&raw const (*skb_addr).data_len).map_err(|c| c as u32)? };

    // skip non-linear packet
    if data_len > 0 {
        return Ok(0);
    }

    let data_ptr =
        unsafe { bpf_probe_read_kernel(&raw const (*skb_addr).data).map_err(|c| c as u32)? }
            as usize;

    let ip_hdr: Ipv4Hdr =
        unsafe { bpf_probe_read_kernel(data_ptr as *const Ipv4Hdr).map_err(|c| c as u32)? };
    if ip_hdr.proto != IpProto::Udp.into() {
        return Ok(0);
    }

    let udp_hdr: UdpHdr = unsafe {
        bpf_probe_read_kernel(&*((data_ptr + Ipv4Hdr::LEN) as *const UdpHdr))
            .map_err(|c| c as u32)?
    };
    if udp_hdr.src_port() == CLIENT_PORT {
        let time: u64 = unsafe { bpf_ktime_get_ns() };
        let _ = TX_TIME_MAP.insert(skb_addr as u64, time, BPF_ANY.into());
    }

    Ok(0)
}

#[kprobe]
pub fn kprobe_tun_net_xmit(ctx: ProbeContext) -> u32 {
    match try_kprobe_tun_net_xmit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
pub fn try_kprobe_tun_net_xmit(ctx: ProbeContext) -> Result<u32, u32> {
    let skbaddr: u64 = ctx.arg(0).ok_or(1u32)?;
    let rx_time: u64 = unsafe { bpf_ktime_get_ns() };
    let mut flag = BPF_RB_NO_WAKEUP as u64;

    if let Some(tx_time) = unsafe { TX_TIME_MAP.get(skbaddr) } {
        let latency: u64 = rx_time - tx_time;
        if let Some(mut buf) = LATENCY_ARRAY.reserve::<u64>(0) {
            unsafe {
                *buf.as_mut_ptr() = latency;
                let count = core::ptr::read_volatile(&raw const EVENT_COUNTER);
                core::ptr::write_volatile(&raw mut EVENT_COUNTER, count + 1);
                if count >= BATCH_SIZE {
                    flag = BPF_RB_FORCE_WAKEUP as u64;
                    core::ptr::write_volatile(&raw mut EVENT_COUNTER, 0);
                }
            };
            buf.submit(flag);
        }
        let _ = TX_TIME_MAP.remove(skbaddr);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
