use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub type Event = Box<dyn FnOnce() + Send + Sync>;

thread_local! {
    static THREAD_TIMER: RefCell<Timer> = RefCell::new(Timer::default());
}

#[derive(Default)]
pub struct Timer {
    events: BTreeMap<Instant, Event>,
}

impl Timer {
    pub fn next_event(&mut self) -> Result<Event, Option<Duration>> {
        let first_time = match self.events.iter().next().map(|(k, _)| *k) {
            Some(x) => x,
            None => return Err(None),
        };
        let now = Instant::now();
        if now >= first_time {
            Ok(self.events.remove(&first_time).unwrap())
        } else {
            Err(Some(first_time.duration_since(now)))
        }
    }

    pub fn add_event(&mut self, delay: Duration, ev: Event) -> bool {
        let target_time = Instant::now().checked_add(delay).unwrap();
        if self.events.contains_key(&target_time) {
            return false;
        }
        self.events.insert(target_time, ev);
        true
    }
}

pub fn with_thread_timer<F: FnOnce(&mut Timer) -> R, R>(f: F) -> R {
    THREAD_TIMER.with(|x| f(&mut *x.borrow_mut()))
}
