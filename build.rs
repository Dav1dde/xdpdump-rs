use std::process::{exit, Command, Stdio};

fn get_libbpf_include() -> std::path::PathBuf {
    let profile = std::env::var("PROFILE").unwrap();
    let mut path = std::path::PathBuf::new();
    path.push("target");
    path.push(&profile);
    path.push("build");
    let libbpf_name = std::fs::read_dir(path.clone())
        .unwrap()
        .find_map(|dir| {
            let name = dir.as_ref().unwrap().file_name().into_string().unwrap();
            if !name.starts_with("libbpf-sys-") {
                return None;
            }
            let mut path = dir.unwrap().path();
            path.push("out");
            if path.exists() {
                Some(name)
            } else {
                None
            }
        })
        .unwrap();
    path.push(libbpf_name);
    path.push("out");
    path.push("include");
    path
}

fn main() {
    let mut compile = Command::new("clang")
        .args(&[
            "-S",
            "-D",
            "__BPF_TRACING__",
            "-Wall",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
            "-Werror",
            "-fno-stack-protector",
            "-I",
            get_libbpf_include().to_str().unwrap(),
            "-O2",
            "-emit-llvm",
            "-c",
            "-g",
            "kern/xdpdump_kern.c",
            "-o",
            "-",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    if !compile.wait().unwrap().success() {
        exit(1);
    }

    let mut link = Command::new("llc")
        .args(&["-march=bpf", "-filetype=obj", "-o", "xdpdump_kern.o", "-"])
        .stdin(Stdio::from(compile.stdout.unwrap()))
        .spawn()
        .unwrap();

    if !link.wait().unwrap().success() {
        exit(2);
    }

    println!("cargo:rerun-if-changed=kern");
}
