use std::process::Command;
use std::path::Path;
fn main() {
    let store = "store";
    let store_home = Path::new(store);
    if store_home.exists() && store_home.is_dir() {
        return;
    };


    let _ = if cfg!(target_os = "linux") {
        Command::new("sh")
            .arg("generate_certificates.sh")
            .arg(store)
            .output()
            .expect("failed to execute process");
    }
    else {
        Command::new("cmd")
            .args(&["./generate_certificates.sh", store])
            .output()
            .expect("failed to execute process");
    };
}
