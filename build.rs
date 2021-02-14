use std::process::{exit, Command, Stdio};

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
