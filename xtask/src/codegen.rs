use aya_gen::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    // TODO: Here there must be a better way to get the app directory
    let dir = PathBuf::from("ebpf-firewall-ebpf/src");
    let names: Vec<&str> = vec!["iphdr", "ethhdr"];
    let bindings = aya_gen::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}