use clap::{App, Arg, ArgGroup};
use perf_event_open_sys::bindings as perf_sys;
use perf_event_open_sys::perf_event_open;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 9216;
pub const NS_IN_SEC: u64 = 1000000000;

#[repr(C)]
union Address {
    v4: u32,
    v6: libc::in6_addr,
}

#[repr(C)]
struct PktMeta {
    src: Address,
    dst: Address,
    port_src: u16,
    port_dst: u16,
    l3_proto: u16,
    l4_proto: u16,
    data_len: u16,
    pkt_len: u16,
    seq: u32,
}

#[repr(C)]
struct Header {
    type_: u32,
    misc: u16,
    size: u16,
}

#[repr(C)]
struct PerfEventSample {
    header: Header,
    timestamp: u64,
    size: u32,
    meta: PktMeta,
    pkt_data: u8,
}

#[derive(Clone, Copy, Debug)]
struct RecordSettings {
    show_payload: bool,
}

fn record_sample(event: &PerfEventSample, settings: &RecordSettings) {
    let mut src = "SRC".to_string();
    let mut dst = "DST".to_string();
    let l3: String;
    let l4: String;

    match event.meta.l3_proto as i32 {
        libc::ETH_P_IP => {
            l3 = "IP ".to_string();
            src = std::net::Ipv4Addr::from(unsafe { u32::from_be(event.meta.src.v4) }).to_string();
            dst = std::net::Ipv4Addr::from(unsafe { u32::from_be(event.meta.dst.v4) }).to_string();
        }
        libc::ETH_P_IPV6 => {
            l3 = "IP6".to_string();
            src = std::net::Ipv6Addr::from(unsafe { event.meta.src.v6.s6_addr }).to_string();
            dst = std::net::Ipv6Addr::from(unsafe { event.meta.dst.v6.s6_addr }).to_string();
        }
        libc::ETH_P_ARP => l3 = "ARP".to_string(),
        proto => l3 = format!("{:#04x}", proto),
    }

    match event.meta.l4_proto as i32 {
        libc::IPPROTO_TCP => l4 = format!("TCP seq {}", event.meta.seq),
        libc::IPPROTO_UDP => l4 = "UDP".to_string(),
        libc::IPPROTO_ICMP => l4 = "ICMP".to_string(),
        _ => l4 = "".to_string(),
    }

    println!(
        "{}.{:0<6} {} {}:{} > {}:{} {}, length {}",
        event.timestamp / NS_IN_SEC,
        (event.timestamp % NS_IN_SEC) / 1000,
        l3,
        src,
        u16::from_be(event.meta.port_src),
        dst,
        u16::from_be(event.meta.port_dst),
        l4,
        event.meta.data_len
    );

    if settings.show_payload {
        let data =
            unsafe { std::slice::from_raw_parts(&event.pkt_data, event.meta.pkt_len as usize) };
        let cfg = pretty_hex::HexConfig {
            title: false,
            ..pretty_hex::HexConfig::default()
        };
        println!("{}", pretty_hex::config_hex(&data, cfg));
    }
}

unsafe extern "C" fn receive_event(
    header: *mut libbpf_sys::perf_event_header,
    ptr: *mut libc::c_void,
) -> i32 {
    let header = header as *const PerfEventSample;
    let settings = ptr as *const RecordSettings;
    if (*header).header.type_ == perf_sys::perf_event_type_PERF_RECORD_SAMPLE {
        record_sample(&*header, &*settings);
    }
    libbpf_sys::LIBBPF_PERF_EVENT_CONT
}

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    }

    let app = App::new("xdpdump")
        .about("simple tcpdump using xdp")
        .arg(
            Arg::with_name("ifname")
                .short("i")
                .value_name("IFNAME")
                .takes_value(true)
                .required(true)
                .help("The network interface"),
        )
        .arg(
            Arg::with_name("hardware")
                .short("H")
                .help("Hardware offloading (xdpoffload)"),
        )
        .arg(
            Arg::with_name("native")
                .short("N")
                .help("Native mode (xdpdrv)"),
        )
        .arg(
            Arg::with_name("skb")
                .short("S")
                .help("SKB mode (xdpgeneric)"),
        )
        .group(
            ArgGroup::with_name("mode")
                .args(&["hardware", "native", "skb"])
                .required(true),
        )
        .arg(
            Arg::with_name("show_payload")
                .short("x")
                .help("Show packet paylod"),
        )
        .arg(
            Arg::with_name("prog")
                .short("p")
                .default_value("xdpdump_kern.o")
                .help("Path to xdp program"),
        )
        .get_matches();

    let interface = xdpdump::Interface::from_name(app.value_of("ifname").unwrap())
        .expect("unable to create interface");

    let mut mode = xdpdump::XdpMode::DrvMode;
    if app.is_present("skb") {
        mode = xdpdump::XdpMode::SkbMode;
    }
    if app.is_present("hardware") {
        mode = xdpdump::XdpMode::HwMode;
    }

    let show_payload = app.is_present("show_payload");

    let prog = PathBuf::from(app.value_of("prog").unwrap());
    let mut prog = xdpdump::XdpProg::new(prog);
    prog.set_mode(mode);
    prog.set_interface(interface);
    let prog = prog.load().unwrap();
    prog.set_link(interface, mode).unwrap();

    let perf_map_fd = prog
        .find_map_by_name("perf_map")
        .expect("perf_map does not exist")
        .fd()
        .unwrap();

    let mut perf_attr = perf_sys::perf_event_attr::default();
    perf_attr.sample_type = perf_sys::perf_event_sample_format_PERF_SAMPLE_RAW
        | perf_sys::perf_event_sample_format_PERF_SAMPLE_TIME;
    perf_attr.type_ = perf_sys::perf_type_id_PERF_TYPE_SOFTWARE;
    perf_attr.config = perf_sys::perf_sw_ids_PERF_COUNT_SW_BPF_OUTPUT as u64;
    perf_attr.__bindgen_anon_2.wakeup_events = 1;

    let n_cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let page_count = 8;
    let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let total_size = pagesize * page_count;
    let mmap_size = pagesize * (page_count + 1);

    let mut poll_fds = Vec::new();
    let mut mmaps = Vec::new();

    for cpu in 0..n_cpus {
        let pmu = unsafe { perf_event_open(&mut perf_attr, -1, cpu as i32, -1, 0) };
        if pmu < 0 {
            panic!("perf open -1");
        }

        if unsafe { libc::ioctl(pmu, PERF_EVENT_IOC_ENABLE, 0) } != 0 {
            panic!("ioctl failed");
        }

        unsafe {
            let mmap = libc::mmap(
                std::ptr::null_mut(),
                mmap_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                pmu,
                0,
            );
            mmaps.push(mmap);

            libbpf_sys::bpf_map_update_elem(
                perf_map_fd,
                &cpu as *const _ as *const libc::c_void,
                &pmu as *const _ as *const libc::c_void,
                libbpf_sys::BPF_ANY.into(),
            );
        }

        poll_fds.push(libc::pollfd {
            fd: pmu,
            events: libc::POLLIN,
            revents: 0,
        });
    }

    let mut tmp_buf = std::ptr::null_mut();
    let mut tmp_len = 0;

    let mut settings = RecordSettings { show_payload };

    while running.load(Ordering::SeqCst) {
        unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as u64, 250) };

        for cpu in 0..n_cpus {
            let poll_fd = poll_fds[cpu as usize];
            let mmap = mmaps[cpu as usize];

            if poll_fd.revents == 0 {
                continue;
            }

            let res = unsafe {
                libbpf_sys::bpf_perf_event_read_simple(
                    mmap,
                    total_size as u64,
                    pagesize as u64,
                    &mut tmp_buf,
                    &mut tmp_len,
                    Some(receive_event),
                    &mut settings as *mut _ as *mut libc::c_void,
                )
            };

            if res != libbpf_sys::LIBBPF_PERF_EVENT_CONT {
                break;
            }
        }
    }

    unsafe { libc::free(tmp_buf) };
    xdpdump::XdpProg::unload(interface);
}
