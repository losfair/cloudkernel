use std::time::Duration;

fn main() {
    unsafe {
        ck_runtime::hook::register_hooks();
    }

    for i in 0..10 {
        let i = i;
        std::thread::spawn(move || {
            loop {
                println!("[{}] tick", i);
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }

    loop {
        println!("[main] tick");
        std::thread::sleep(Duration::from_secs(1));
    }
}
