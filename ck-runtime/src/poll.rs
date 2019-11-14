use crate::{ipc, timer};
use byteorder::{ByteOrder, LittleEndian};
use nix::unistd::close;
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

pub type SessionCallback = Box<Fn(Incoming) + Send + Sync>;

lazy_static! {
    pub static ref SESSIONS: Mutex<HashMap<(u128, u64), Arc<SessionCallback>>> =
        Mutex::new(HashMap::new());
}

#[derive(Default, Clone, Debug)]
pub struct Incoming {
    pub sender: u128,
    pub session: u64,
    pub tag: u32,
    pub data: Vec<u8>,
    fds: Vec<Option<RawFd>>,
}

impl Incoming {
    pub fn take_fd(&mut self, idx: usize) -> Option<RawFd> {
        if idx >= self.fds.len() {
            None
        } else {
            self.fds[idx].take()
        }
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        for fd in &self.fds {
            if let Some(fd) = *fd {
                match close(fd) {
                    _ => {}
                }
            }
        }
    }
}

pub fn start_poll() {
    let mut buf: Vec<u8> = vec![0; 65536];

    loop {
        let maybe_ev = timer::with_thread_timer(|x| x.next_event());
        match maybe_ev {
            Ok(ev) => {
                ev();
            }
            Err(maybe_duration) => {
                let mut incoming = Incoming::default();
                let mut delay: [u8; 8] = [0; 8];
                if let Some(x) = maybe_duration {
                    let mut millis = x.as_millis() as u64;
                    if millis == 0 {
                        millis = 1; // FIXME: Why?
                    }
                    LittleEndian::write_u64(&mut delay, millis);
                }
                ipc::send_message(0, 0, ipc::KernelMessageType::POLL as u32, &delay);
                if let Some((n, fds)) = ipc::recv_message_with_fds(
                    &mut incoming.sender,
                    &mut incoming.session,
                    &mut incoming.tag,
                    &mut buf,
                ) {
                    if (incoming.sender != std::u128::MAX) {
                        incoming.data = buf[..n].to_vec();
                        incoming.fds = fds.into_iter().map(|x| Some(x)).collect();
                        dispatch_message(incoming);
                    }
                }
            }
        }
    }
}

fn dispatch_message(mut incoming: Incoming) {
    let callback = SESSIONS
        .lock()
        .unwrap()
        .get(&(incoming.sender, incoming.session))
        .map(|x| x.clone());
    if let Some(x) = callback {
        x(incoming);
        return;
    }

    match (incoming.sender, incoming.tag) {
        (0, _) => handle_kernel_message(incoming.session, incoming.tag, &mut incoming.data),
        (_, x) if x == ipc::RtMessageType::EntangleRequest as u32 => {
            crate::tangle::handle_incoming(incoming);
        }
        _ => {}
    }
}

fn handle_kernel_message(session: u64, tag: u32, data: &mut [u8]) {
    use ipc::KernelMessageType;
    use std::convert::TryFrom;

    let tag = match KernelMessageType::try_from(tag) {
        Ok(x) => x,
        Err(e) => {
            println!("Invalid message type. Error: {:?}", e);
            return;
        }
    };

    match tag {
        KernelMessageType::IP_PACKET => {
            crate::net::ip_input(data);
        }
        _ => {
            println!("Unknown tag: {:?}", tag);
        }
    }
}
