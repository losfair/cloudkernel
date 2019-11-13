use std::env;
use ck_runtime::{snapshot, process};
use std::time::Duration;

fn main() {
    let name = env::args().nth(1).expect("expecting name");
    let pid = process::create(&name).expect("process creation failed");
    println!("pid = {:032x}", pid);
    std::thread::sleep(Duration::from_secs(3));
    println!("begin snapshot");
    let image_name = snapshot::create(pid).expect("unable to take snapshot");
    println!("snapshot image name = {}", image_name);
}
