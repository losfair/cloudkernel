use crate::poll::Incoming;
use crate::{ipc, timer};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::unistd::close;
use std::collections::HashMap;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub type ServiceCallback = Fn(UnixStream) + Send + Sync;

lazy_static! {
    static ref SERVICES: Mutex<HashMap<String, Arc<ServiceCallback>>> = Mutex::new(HashMap::new());
}

pub fn entangle<F: FnOnce(Result<UnixStream, String>) + Send + Sync + 'static>(
    peer_pid: u128,
    service_name: &str,
    callback: F,
) {
    let (local, remote) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .unwrap();
    let session: u64 = rand::random();

    let service_name = service_name.as_bytes();

    ipc::send_message_with_fds(
        peer_pid,
        session,
        ipc::RtMessageType::EntangleRequest as u32,
        service_name,
        &[remote],
    );
    match close(remote) {
        _ => {}
    }

    let callback = Arc::new(Mutex::new(Some(callback)));
    let callback2 = callback.clone();

    crate::poll::SESSIONS.lock().unwrap().insert(
        (peer_pid, session),
        Arc::new(Box::new(move |mut incoming| {
            let callback = callback2.lock().unwrap().take();
            if let Some(cb) = callback {
                crate::poll::SESSIONS
                    .lock()
                    .unwrap()
                    .remove(&(peer_pid, session));
                if incoming.tag == ipc::RtMessageType::EntangleOffer as u32 {
                    cb(Ok(unsafe { UnixStream::from_raw_fd(local) }));
                    return;
                }
                cb(Err("invalid response".into()));
            }
        })),
    );
    timer::with_thread_timer(|timer| loop {
        let callback = callback.clone();
        if timer.add_event(
            Duration::from_secs(1),
            Box::new(move || {
                let callback = callback.lock().unwrap().take();
                if let Some(cb) = callback {
                    crate::poll::SESSIONS
                        .lock()
                        .unwrap()
                        .remove(&(peer_pid, session));
                    cb(Err("timeout".into()));
                }
            }),
        ) {
            break;
        }
    });
}

pub(crate) fn handle_incoming(mut incoming: Incoming) {
    let service_name = match std::str::from_utf8(&incoming.data) {
        Ok(x) => x,
        Err(_) => return,
    };

    let services = SERVICES.lock().unwrap();
    if let Some(ref callback) = services.get(service_name) {
        if let Some(fd) = incoming.take_fd(0) {
            let callback = (*callback).clone();
            drop(services);
            callback(unsafe { UnixStream::from_raw_fd(fd) });
            ipc::send_message(
                incoming.sender,
                incoming.session,
                ipc::RtMessageType::EntangleOffer as u32,
                &[],
            );
        }
    }
}

pub fn add_service<F: Fn(UnixStream) + Send + Sync + 'static>(name: String, cb: F) {
    SERVICES.lock().unwrap().insert(name, Arc::new(cb));
}
