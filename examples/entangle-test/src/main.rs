use std::time::Duration;
use std::io::{Read, Write};

fn run_peer(peer_pid: String) {
    let peer_pid = u128::from_str_radix(&peer_pid, 16).unwrap();
    ck_runtime::timer::with_thread_timer(|timer| {
        timer.add_event(Duration::from_millis(10), Box::new(move || {
            println!("Trying to entangle with peer {:032x}", peer_pid);
            ck_runtime::tangle::entangle(peer_pid, "test-service", |result| {
                let mut stream = match result {
                    Ok(s) => s,
                    Err(e) => {
                        println!("Unable to entangle: {}", e);
                        return;
                    }
                };
                let mut text = String::new();
                match stream.read_to_string(&mut text) {
                    Ok(_) => println!("Data from remote peer: {}", text),
                    Err(e) => println!("Error receiving from remote peer: {:?}", e),
                }
            })
        }));
    });
    ck_runtime::poll::start_poll();
}

fn run_master() {
    ck_runtime::tangle::add_service("test-service".into(), |mut stream| {
        match stream.write_all(b"Hello from test-service.") {
            Ok(_) => {},
            Err(e) => println!("write_all failed: {:?}", e),
        }
    });
    ck_runtime::poll::start_poll();
}

fn main() {
    unsafe {
        ck_runtime::hook::register_hooks();
    }
    match std::env::args().nth(1) {
        Some(x) => run_peer(x),
        None => run_master(),
    }
}
