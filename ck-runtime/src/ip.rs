use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use byteorder::{ByteOrder, LittleEndian};
use crate::ipc;
use nix::sys::mman::{ProtFlags, MapFlags, mmap};
use std::os::unix::io::{RawFd};
use std::sync::Mutex;
use std::time::Duration;
use libc::{__errno_location, timespec, syscall, FUTEX_WAIT, FUTEX_WAKE};
use std::cell::UnsafeCell;

unsafe fn futex(
    uaddr: *mut i32,
    futex_op: i32,
    val: i32,
    timeout: *const timespec,
    uaddr2: *mut i32,
    val3: i32
) -> i32 {
    syscall(
        libc::SYS_futex,
        uaddr,
        futex_op,
        val,
        timeout,
        uaddr2,
        val3,
    ) as i32
}

#[repr(C)]
struct Element {
    filled: AtomicU32,
    _padding: u32,
    len: AtomicU64,
    data: UnsafeCell<[u8; 2048 - 16]>,
}

unsafe impl Send for Element {}
unsafe impl Sync for Element {}

struct SharedQueue {
    elements: &'static [Element],
    next_element: usize,
}

struct IPQueue {
    tun: RawFd,
    tx: Mutex<SharedQueue>,
    rx: Mutex<SharedQueue>,
}

impl SharedQueue {
    unsafe fn leaky_map(fd: RawFd, n: usize) -> SharedQueue {
        let map_size = std::mem::size_of::<Element>() * n;
        let mapped = mmap(
            std::ptr::null_mut(), map_size as _,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE, MapFlags::MAP_SHARED, 
            fd, 0
        ).unwrap() as *mut Element;
        SharedQueue {
            elements: std::slice::from_raw_parts_mut(
                mapped,
                n,
            ),
            next_element: 0,
        }
    }
}

impl IPQueue {
    fn leaky_new(n: usize) -> Result<IPQueue, String> {
        assert!(std::mem::size_of::<Element>() == 2048);

        let tun_fd: RawFd = std::env::var("CK_TUN").map(|x| x.parse().unwrap()).map_err(|_| "CK_TUN required".to_string())?;

        let mut size_buf: [u8; 4] = [0; 4];
        LittleEndian::write_u32(&mut size_buf, n as u32);
        ipc::trivial_kernel_request(ipc::KernelMessageType::IP_QUEUE_OPEN, &size_buf)?;

        let mut sender: u128 = 0;
        let mut session: u64 = 0;
        let mut tag: u32 = 0;
        let fds = match ipc::recv_message_with_fds(&mut sender, &mut session, &mut tag, &mut []) {
            Some((_, fds)) => fds,
            None => return Err("cannot receive file descriptors".into())
        };
        if fds.len() != 2 {
            return Err("invalid size of file descriptors".into());
        }
        let tx_fd = fds[0];
        let rx_fd = fds[1];
        Ok(unsafe { IPQueue {
            tun: tun_fd,
            tx: Mutex::new(SharedQueue::leaky_map(tx_fd, n)),
            rx: Mutex::new(SharedQueue::leaky_map(rx_fd, n)),
        } })
    }

    unsafe fn run_tx_worker(&self) {
        let mut tx = self.tx.lock().unwrap();
        loop {
            let element = &tx.elements[tx.next_element];
            if element.filled.load(Ordering::SeqCst) != 0 {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }

            let data = &mut *element.data.get();
            let n = match nix::unistd::read(self.tun, data) {
                Ok(0) => continue,
                Ok(x) => x,
                Err(e) => {
                    println!("tun read failed: {:?}", e);
                    continue;
                }
            };
            element.len.store(n as u64, Ordering::SeqCst);
            element.filled.store(1, Ordering::SeqCst);
            futex(
                &element.filled as *const AtomicU32 as *mut i32,
                FUTEX_WAKE,
                1,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            );
            
            if tx.next_element + 1 == tx.elements.len() {
                tx.next_element = 0;
            } else {
                tx.next_element += 1;
            }
        }
    }

    unsafe fn run_rx_worker(&self) {
        let mut rx = self.rx.lock().unwrap();
        let errno_location = __errno_location();
        loop {
            let element = &rx.elements[rx.next_element];
            while element.filled.load(Ordering::SeqCst) == 0 {
                let code = futex(
                    &element.filled as *const AtomicU32 as *mut i32,
                    FUTEX_WAIT,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    0,
                );
                let err = *errno_location;
                match (code, err) {
                    (0, _) => {},
                    (-1, libc::EINTR) => {},
                    (-1, libc::EAGAIN) => {},
                    _ => panic!("unexpected result from FUTEX_WAIT"),
                }
            }
            let data = &(*element.data.get())[..element.len.load(Ordering::SeqCst) as usize];
            match nix::unistd::write(self.tun, data) { _ => {} }
            element.filled.store(0, Ordering::SeqCst);
            if rx.next_element + 1 == rx.elements.len() {
                rx.next_element = 0;
            } else {
                rx.next_element += 1;
            }
        }
    }
}

pub unsafe fn start() {
    use std::sync::Arc;
    let q = Arc::new(IPQueue::leaky_new(512).unwrap());
    {
        let q = q.clone();
        std::thread::spawn(move || q.run_tx_worker());
    }
    {
        let q = q.clone();
        std::thread::spawn(move || q.run_rx_worker());
    }
}
