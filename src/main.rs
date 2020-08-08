use std::path::Path;
use std::process::Command;

const BOOTFILE_NAME: &'static str = "barberslice.boot";
const KERNEL_NAME: &'static str = "barberslice.kern";
const KERNEL_PATH: &'static str = "kernel/target/x86_64-pc-windows-msvc/release/kernel.exe";
const SNAPSHOT_REGS: &'static str = "SNAPSHOT_regs";

fn main() -> std::io::Result<()> {
    const DEPLOY_PATHS: &[&str] = &[
        "C:/Users/rando/tftp",
        "C:/Users/rando/workspace/barberslice/tftp-server",
        "C:/Users/rando/workspace/barberslice/emu",
    ];

    let args: Vec<String> = std::env::args().collect();

    if args.len() == 2 && args[1] == "clean" {
        /* Remove files */
        for filename in &["stage1.flat", BOOTFILE_NAME] {
            if Path::new(filename).exists() {
                print!("Removing {}...\n", filename);
                std::fs::remove_file(filename).expect("Failed to remove file");
            }
        }

        /* Clean bootloader */
        print!("Cleaning bootloader...\n");
        std::env::set_current_dir("bootloader").expect("Failed to chdir to bootloader");
        let status = Command::new("cargo")
            .arg("clean")
            .status()
            .expect("Failed to invoke bootloader clean");
        assert!(status.success(), "Failed to clean bootloader");

        /* Clean kernel */
        print!("Cleaning kernel...\n");
        std::env::set_current_dir("../kernel").expect("Failed to chdir to kernel");
        let status = Command::new("cargo")
            .arg("clean")
            .status()
            .expect("Failed to invoke kernel clean");
        assert!(status.success(), "Failed to clean kernel");

        print!("Cleaned\n");
        return Ok(());
    } else if args.len() == 2 && args[1] == "olddoc" {
        print!("Documenting bootloader...\n");
        std::env::set_current_dir("bootloader").expect("Failed to chdir to bootloader");
        let bootloader_status = Command::new("cargo")
            .args(&["doc", "--release"])
            .env("RUSTDOCFLAGS", "--document-private-items")
            .status()
            .expect("Failed to invoke doc of bootloader");
        assert!(bootloader_status.success(), "Failed to doc bootloader");

        print!("Documenting kernel...\n");
        std::env::set_current_dir("../kernel").expect("Failed to chdir to kernel");
        let bootloader_status = Command::new("cargo")
            .args(&["doc", "--release"])
            .env("RUSTDOCFLAGS", "--document-private-items")
            .status()
            .expect("Failed to invoke doc of kernel");
        assert!(bootloader_status.success(), "Failed to doc kernel");

        print!("Documenting done!\n");
        return Ok(());
    }

    /* Build stage1. This is the rust portion of the bootloader */
    print!("Building stage1...\n");
    std::env::set_current_dir("bootloader").expect("Failed to chdir to bootloader");
    let bootloader_status = Command::new("cargo")
        .args(&["build", "--release"])
        .status()
        .expect("Failed to invoke build of bootloader");
    assert!(bootloader_status.success(), "Failed to build bootloader");

    /* Flatten the bootloader. This will take the PE produced by the bootloader
     * and convert it to an in-memory loaded representation such that it can
     * be incbined by the stage0.
     */
    print!("Flattening bootloader...\n");
    std::env::set_current_dir("..").expect("Failed to chdir to original dir");
    let flatten_status = Command::new("python")
        .args(&[
            "flatten_pe.py",
            "bootloader/target/i586-pc-windows-msvc/release/stage1.exe",
            "stage1.flat",
        ])
        .status()
        .expect("Failed to invoke flatten script");
    assert!(flatten_status.success(), "Failed to flatten bootloader");

    /* Assemble stage0. This produces the final bootable bootloader. This
     * is a tiny trampoline 16-bit assembly snippit that switches to protected
     * mode and jumps into the incbined flattened PE file.
     */
    print!("Assembling bootloader...\n");
    let stage0_status = Command::new("nasm")
        .args(&["-f", "bin", "-o", BOOTFILE_NAME, "bootloader/stage0.asm"])
        .status()
        .expect("Failed to invoke NASM for stage0");
    assert!(stage0_status.success(), "Failed to assemble bootloader");

    print!("Bootloader successfully built\n");

    let md = std::fs::metadata(BOOTFILE_NAME).expect("Failed to get metadata for bootloader");
    assert!(md.is_file(), "Bootloader is not a file!?");

    print!(
        "Bootloader size is {} bytes ({:8.4}%)\n",
        md.len(),
        md.len() as f64 / (32. * 1024.) * 100.0
    );

    assert!(md.len() <= (32 * 1024), "Bootloader is too large!");

    print!("Deploying bootloader...\n");

    /* Attempt to deploy bootloader to various different TFTP directories.
     * Since I work with this codebase on multiple networks and systems, this
     * is just a list of the paths that work on each for deployment. It'll try
     * to deploy to all of them.
     */
    for tftpd_dir in DEPLOY_PATHS {
        if !Path::new(tftpd_dir).exists() {
            continue;
        }

        print!("Deploying bootloader to {}...\n", tftpd_dir);
        std::fs::copy(BOOTFILE_NAME, Path::new(tftpd_dir).join(BOOTFILE_NAME))
            .expect("Failed to copy file");
    }

    print!("Bootloader successfully deployed\n");

    /* Build kernel */
    print!("Building kernel...\n");

    std::env::set_current_dir("kernel").expect("Failed to chdir to kernel");

    let kernel_status = Command::new("cargo")
        .args(&["build", "--release"])
        .status()
        .expect("Failed to invoke build of kernel");
    assert!(kernel_status.success(), "Failed to build kernel");

    std::env::set_current_dir("..").expect("Failed to chdir to original dir");

    /* Deploy kernel, same as bootloader */
    for tftpd_dir in DEPLOY_PATHS {
        if !Path::new(tftpd_dir).exists() {
            continue;
        }

        print!("Deploying kernel to {}...\n", tftpd_dir);
        std::fs::copy(KERNEL_PATH, Path::new(tftpd_dir).join(KERNEL_NAME))
            .expect("Failed to copy file");
    }

    /* Setup snapshot files in the TFTP dir */
    std::env::set_current_dir("snapshot").expect("Failed to chdir to snapshot");
    let snapshot_status = Command::new("cargo")
        .args(&["run", "--release"])
        .status()
        .expect("Failed to invoke build of snapshot");
    assert!(snapshot_status.success(), "Failed to build snapshot");
    std::env::set_current_dir("..").expect("Failed to chdir to original dir");

    std::fs::copy(Path::new("snapshot").join(SNAPSHOT_REGS), Path::new("tftp-server").join(SNAPSHOT_REGS))
        .expect("Failed to copy SNAPSHOT_regs");

    /* Setup snapshot files in the TFTP dir */
    std::env::set_current_dir("tftp-server").expect("Failed to chdir to rustftp");
    let snapshot_status = Command::new("cargo")
        .args(&["run", "--release"])
        .status()
        .expect("Failed to invoke build of snapshot");
    assert!(snapshot_status.success(), "Failed to build ftp server");

    Ok(())
}
