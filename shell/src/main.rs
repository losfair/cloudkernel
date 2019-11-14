use std::io::{Write, BufRead};

fn main() {
    unsafe {
        ck_runtime::hook::register_hooks();
    }
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let handle = stdin.lock();
    let mut stdin_it = handle.lines();

    loop {
        print!("> ");
        stdout.flush();
        let line: Vec<String> = stdin_it.next().unwrap().unwrap().split(" ").filter(|x| x.len() > 0).map(|x| x.to_string()).collect();
        if line.len() == 0 {
            continue;
        }
        match ck_runtime::process::create(&line) {
            Ok(pid) => println!("Process created. PID = {:032x}", pid),
            Err(e) => println!("Process creation failed. Error = {}", e),
        }
    }
}
