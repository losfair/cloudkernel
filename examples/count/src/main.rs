use std::time::Duration;

fn main() {
    for i in 0.. {
        println!("{}", i);
        std::thread::sleep(Duration::from_secs(1));
    }
}
