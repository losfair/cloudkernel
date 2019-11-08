use std::time::{Duration, SystemTime};
use std::collections::HashSet;
use ck_runtime::ipc;
use ck_runtime::process;

fn main() {
    unsafe {
        ck_runtime::hook::register_hooks();
    }
    let root_pid = ck_runtime::process::getpid();
    println!("Application starting. PID = {:032x}", root_pid);

    let t_start = SystemTime::now();
    match ck_runtime::snapshot::snapshot_me() {
        0 => {
            //println!("Finished process creation. Time elapsed = {:?}", SystemTime::now().duration_since(t_start));
            ipc::send_message(root_pid, 0, 1, b"OK")
        }
        1 => {
            loop {
                let mut pids: HashSet<u128> = HashSet::new();
                for _ in 0..128 {
                    let pid = process::create(format!("snapshot:{:032x}_0.0.0", root_pid).as_str()).unwrap();
                    pids.insert(pid);
                }
                
                let mut sender: u128 = 0;
                let mut session: u64 = 0;
                let mut tag: u32 = 0;
                let mut data = vec![0u8; 65536];

                loop {
                    let n = ipc::poll(&mut sender, &mut session, &mut tag, &mut data).expect("poll failed");
                    let data = &data[..n];
                    if pids.contains(&sender) {
                        assert_eq!(data, b"OK");
                        pids.remove(&sender);
                        let t_end = SystemTime::now();
                        println!("Received response ({} remaining). Time elapsed = {:?}", pids.len(), SystemTime::now().duration_since(t_start));
                        if pids.len() == 0 {
                            break;
                        }
                    }
                }
            }
        }
        _ => panic!("snapshot failed")
    }
}
