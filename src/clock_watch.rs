use std::{borrow::Borrow, time::Duration};

use tokio::sync::watch;

use crate::{calculate_timeslot, get_unix_timestamp, SLOT_LENGTH};

/// A tokio sync watch that sends a timeslot when a new timeslot is reached
/// Then the blockchain actor can stake when it sees the update

#[derive(Clone)]
pub struct ClockWatch {
    receiver: watch::Receiver<u64>,
}

impl ClockWatch {
    pub fn start(starttime: u128) -> Self {
        let (sender, receiver) = watch::channel(calculate_timeslot(starttime));
       
        // start the clock
        tokio::spawn(async move {
            loop {
                let last_timeslot = calculate_timeslot(starttime);
                let next_timeslot_start = starttime + (last_timeslot as u128 + 1) * SLOT_LENGTH;
                let time_to_sleep = next_timeslot_start - get_unix_timestamp();
                tokio::time::sleep(Duration::from_millis(time_to_sleep as u64)).await;
                let current_timeslot = calculate_timeslot(starttime);
                if current_timeslot != last_timeslot {
                    sender.send(current_timeslot).unwrap();
                }
            }
        });

        Self {
            receiver
        }
    }

    pub async fn wait_for_update(&mut self) -> u64 {
        self.receiver.changed().await.unwrap();
        *(self.receiver.borrow())
    }
} 