use std::net::UdpSocket;
use ck_runtime::process::ProcessCreationInfo;

fn main() {
    unsafe {
        ck_runtime::hook::register_hooks();
    }
    
    println!("Application starting. PID = {:032x}", ck_runtime::process::getpid());
    //let mut socket = UdpSocket::bind("127.0.0.1:3366").unwrap();
    ck_runtime::net::register_ipv4_address("192.168.22.10".parse().unwrap()).unwrap();
    println!("Address registered");

    match ck_runtime::snapshot::snapshot_me() {
        0 => {
            println!("resumed process");
        }
        1 => {
            let result = ProcessCreationInfo::new(format!("snapshot:{:032x}_0.0.0", ck_runtime::process::getpid()).as_str(), false).send();
            println!("process creation result = {:?}", result);
        }
        _ => panic!("snapshot failed")
    }
    
    ck_runtime::run_event_loop();
}
