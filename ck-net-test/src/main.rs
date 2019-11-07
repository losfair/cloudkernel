use std::net::UdpSocket;

fn main() {
    unsafe {
        ck_runtime::hook::register_hooks();
    }
    
    println!("Application starting");
    //let mut socket = UdpSocket::bind("127.0.0.1:3366").unwrap();
    ck_runtime::net::register_ipv4_address("192.168.22.10".parse().unwrap()).unwrap();
    println!("Address registered");
    ck_runtime::run_event_loop();
}
