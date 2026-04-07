fn main() {
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-cdylib-link-arg=-undefined");
        println!("cargo:rustc-cdylib-link-arg=dynamic_lookup");
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    } else if cfg!(target_os = "linux") {
        println!(
            "cargo:rustc-link-arg=\
             -Wl,--unresolved-symbols=ignore-in-object-files"
        );
    }
}
