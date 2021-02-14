use std::ffi::CString;
use std::path::PathBuf;

use libbpf_sys;
use libc;

pub fn if_nametoindex(ifname: &str) -> u32 {
    if let Ok(ifname) = CString::new(ifname) {
        unsafe { libc::if_nametoindex(ifname.as_ptr()) }
    } else {
        0
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Interface {
    index: u32,
}

impl Interface {
    pub fn new(index: u32) -> Self {
        Self { index }
    }

    pub fn from_name(name: &str) -> anyhow::Result<Interface> {
        let ifindex = if_nametoindex(name);
        if ifindex == 0 {
            anyhow::bail!("invalid interface name {}", name);
        }
        Ok(Self::new(ifindex))
    }

    pub fn ifindex(&self) -> u32 {
        self.index
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XdpMode {
    SkbMode,
    DrvMode,
    HwMode,
}

impl XdpMode {
    pub fn as_u32(&self) -> u32 {
        match self {
            XdpMode::SkbMode => libbpf_sys::XDP_FLAGS_SKB_MODE,
            XdpMode::DrvMode => libbpf_sys::XDP_FLAGS_DRV_MODE,
            XdpMode::HwMode => libbpf_sys::XDP_FLAGS_HW_MODE,
        }
    }
}

pub struct XdpProg {
    path: PathBuf,
    mode: XdpMode,
    ifindex: i32,
    log_level: i32,
}

impl XdpProg {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            mode: XdpMode::SkbMode,
            ifindex: 0,
            log_level: 0,
        }
    }

    pub fn unload(interface: Interface) {
        unsafe {
            libbpf_sys::bpf_set_link_xdp_fd(interface.ifindex() as i32, -1, 0);
        }
    }

    pub fn set_mode(&mut self, mode: XdpMode) {
        self.mode = mode;
    }

    pub fn set_interface(&mut self, interface: Interface) {
        self.ifindex = interface.ifindex() as i32;
    }

    pub fn load(self) -> anyhow::Result<LoadedXdpProg> {
        let file = self.path.to_str().unwrap();
        let file = CString::new(file)?;
        let file = file.as_ptr();
        let ifindex = if self.mode == XdpMode::HwMode {
            self.ifindex
        } else {
            0
        };

        let args = libbpf_sys::bpf_prog_load_attr {
            prog_type: libbpf_sys::BPF_PROG_TYPE_XDP,
            expected_attach_type: 0,
            ifindex,
            file,
            log_level: self.log_level as i32,
            prog_flags: self.mode.as_u32() as i32,
        };

        let mut prog_fd = 0;
        let mut obj: *mut libbpf_sys::bpf_object = std::ptr::null_mut();
        unsafe {
            if libbpf_sys::bpf_prog_load_xattr(&args, &mut obj, &mut prog_fd) != 0 {
                return Err(anyhow::anyhow!("bpf_prg_load_xattr failed"));
            }
        }

        Ok(LoadedXdpProg::new(obj, prog_fd))
    }
}

pub struct LoadedXdpProg {
    obj: *mut libbpf_sys::bpf_object,
    prog_fd: i32,
}

impl LoadedXdpProg {
    fn new(obj: *mut libbpf_sys::bpf_object, prog_fd: i32) -> Self {
        Self { obj, prog_fd }
    }

    pub fn set_link(&self, interface: Interface, mode: XdpMode) -> anyhow::Result<()> {
        unsafe {
            if libbpf_sys::bpf_set_link_xdp_fd(
                interface.ifindex() as i32,
                self.prog_fd,
                mode.as_u32(),
            ) < 0
            {
                return Err(anyhow::anyhow!("bpf_set_link_xdp_fd failed"));
            }
        }
        Ok(())
    }

    pub fn find_map_by_name(&self, name: &str) -> Option<Map> {
        if let Ok(name) = CString::new(name.to_string()) {
            unsafe { libbpf_sys::bpf_object__find_map_by_name(self.obj, name.as_ptr()).as_mut() }
                .map(|p| Map::new(p))
        } else {
            None
        }
    }
}

pub struct Map {
    map: *mut libbpf_sys::bpf_map,
}

impl Map {
    fn new(map: *mut libbpf_sys::bpf_map) -> Self {
        Self { map }
    }

    pub fn fd(&self) -> Option<i32> {
        let fd = unsafe { libbpf_sys::bpf_map__fd(self.map) };
        if fd < 0 {
            None
        } else {
            Some(fd)
        }
    }
}
