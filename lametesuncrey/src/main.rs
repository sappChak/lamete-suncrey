use std::os::fd::AsRawFd;

use aya::{
    maps::RingBuf,
    programs::{KProbe, TracePoint},
};
#[rustfmt::skip]
use log::{info};
use clap::Parser;
use tokio::{io::unix::AsyncFd, signal, sync::mpsc};

#[derive(Debug, Parser)]
struct Args {
    /// Number of latency measurements
    #[arg(short, long, default_value_t = 100_000)]
    count: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let Args { count } = Args::parse();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lametesuncrey"
    )))?;
    if let Ok(logger) = aya_log::EbpfLogger::init(&mut ebpf) {
        let mut logger =
            tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
        tokio::task::spawn(async move {
            loop {
                let mut guard = logger.readable_mut().await.unwrap();
                guard.get_inner_mut().flush();
                guard.clear_ready();
            }
        });
    }
    let trace_program: &mut TracePoint = ebpf
        .program_mut("trace_netif_receive_skb")
        .unwrap()
        .try_into()?;
    trace_program.load()?;
    trace_program.attach("net", "netif_receive_skb")?;

    let kprobe_program: &mut KProbe = ebpf
        .program_mut("kprobe_tun_net_xmit")
        .unwrap()
        .try_into()?;
    kprobe_program.load()?;
    kprobe_program.attach("tun_net_xmit", 0)?;

    let (tx, mut rx) = mpsc::channel::<Vec<u64>>(1);
    let mut latencies = RingBuf::try_from(ebpf.take_map("LATENCY_ARRAY").unwrap())?;
    let mut async_fd = AsyncFd::new(latencies.as_raw_fd())?;

    let mut batch = Vec::<u64>::with_capacity(count);

    tokio::spawn(async move {
        loop {
            let mut guard = async_fd.readable_mut().await.unwrap();

            while let Some(item) = latencies.next() {
                if item.len() >= std::mem::size_of::<u64>() {
                    // SAFETY: size of the type is checked
                    let delta: u64 = unsafe { std::ptr::read(item.as_ptr() as *const u64) };
                    batch.push(delta);

                    if batch.len() == batch.capacity() {
                        if tx.send(batch).await.is_err() {
                            eprint!("error sending batched latencies");
                        }
                        batch = Vec::<u64>::with_capacity(count);
                    }
                }
            }

            guard.clear_ready();
        }
    });

    tokio::spawn(async move {
        let mut counter = 0;
        while let Some(batch) = rx.recv().await {
            if !batch.is_empty() {
                let n = batch.len() as u64;
                let sum: u64 = batch.iter().sum();
                let mean = sum as f64 / n as f64;
                let sample_variance = batch
                    .iter()
                    .map(|&x| {
                        let diff = x as f64 - mean;
                        diff * diff
                    })
                    .sum::<f64>()
                    / (n as f64 - 1.0);
                let std_dev = sample_variance.sqrt();
                info!(
                    "{counter}: batch size: {n}; sample mean: {:.3} ns; std-dev: {:.3} ns",
                    mean, std_dev
                );
                counter += 1;
            }
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
