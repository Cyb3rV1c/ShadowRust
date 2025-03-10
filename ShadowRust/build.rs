fn main() {
    cc::Build::new()
        .file("syscalls.asm")
        .compile("syscalls");
}
