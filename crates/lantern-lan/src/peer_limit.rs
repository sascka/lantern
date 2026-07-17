// SPDX-License-Identifier: MPL-2.0

use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::LanError;

pub const MAX_ACTIVE_CONNECTIONS_PER_PEER: u8 = 1;
pub const MAX_CONNECTION_ATTEMPTS_PER_PEER_WINDOW: u8 = 8;
pub const MAX_TRACKED_PEERS: usize = 256;
pub const PEER_ATTEMPT_WINDOW_SECONDS: u64 = 60;

const PEER_ATTEMPT_WINDOW: Duration = Duration::from_secs(PEER_ATTEMPT_WINDOW_SECONDS);

#[derive(Clone, Copy)]
struct PeerState {
    window_started: Instant,
    attempts: u8,
    active: u8,
}

impl PeerState {
    const fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            attempts: 0,
            active: 0,
        }
    }

    fn reset_window_if_due(&mut self, now: Instant) {
        if now.duration_since(self.window_started) >= PEER_ATTEMPT_WINDOW {
            self.window_started = now;
            self.attempts = 0;
        }
    }
}

#[derive(Default)]
struct PeerTable {
    peers: BTreeMap<IpAddr, PeerState>,
}

impl PeerTable {
    fn reserve(&mut self, peer: IpAddr, now: Instant) -> Result<(), LanError> {
        self.remove_expired_inactive(now);
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_TRACKED_PEERS {
            return Err(LanError::PeerLimitReached);
        }

        let state = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerState::new(now));
        state.reset_window_if_due(now);
        if state.attempts >= MAX_CONNECTION_ATTEMPTS_PER_PEER_WINDOW {
            return Err(LanError::PeerLimitReached);
        }
        state.attempts = state
            .attempts
            .checked_add(1)
            .ok_or(LanError::PeerLimitReached)?;
        if state.active >= MAX_ACTIVE_CONNECTIONS_PER_PEER {
            return Err(LanError::PeerLimitReached);
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or(LanError::PeerLimitReached)?;
        Ok(())
    }

    fn release(&mut self, peer: IpAddr) {
        if let Some(state) = self.peers.get_mut(&peer) {
            state.active = state.active.saturating_sub(1);
        }
    }

    fn remove_expired_inactive(&mut self, now: Instant) {
        self.peers.retain(|_, state| {
            state.active > 0 || now.duration_since(state.window_started) < PEER_ATTEMPT_WINDOW
        });
    }
}

#[derive(Clone, Default)]
pub(crate) struct PeerLimiter {
    table: Arc<Mutex<PeerTable>>,
}

impl PeerLimiter {
    pub(crate) fn reserve(&self, peer: IpAddr) -> Result<PeerLease, LanError> {
        self.reserve_at(peer, Instant::now())
    }

    fn reserve_at(&self, peer: IpAddr, now: Instant) -> Result<PeerLease, LanError> {
        self.table
            .lock()
            .map_err(|_| LanError::PeerLimitUnavailable)?
            .reserve(peer, now)?;
        Ok(PeerLease {
            peer,
            limiter: self.clone(),
        })
    }

    fn release(&self, peer: IpAddr) {
        if let Ok(mut table) = self.table.lock() {
            table.release(peer);
        }
    }
}

pub(crate) struct PeerLease {
    peer: IpAddr,
    limiter: PeerLimiter,
}

impl Drop for PeerLease {
    fn drop(&mut self) {
        self.limiter.release(self.peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn active_connection_blocks_a_second_connection_from_the_same_peer() {
        let limiter = PeerLimiter::default();
        let now = Instant::now();
        let first = limiter.reserve_at(peer(1), now);
        let Ok(first) = first else {
            panic!("first peer connection should be admitted");
        };

        assert!(matches!(
            limiter.reserve_at(peer(1), now),
            Err(LanError::PeerLimitReached)
        ));
        drop(first);
        assert!(limiter.reserve_at(peer(1), now).is_ok());
    }

    #[test]
    fn reconnect_attempts_are_limited_across_separate_connections() {
        let limiter = PeerLimiter::default();
        let now = Instant::now();
        for _ in 0..MAX_CONNECTION_ATTEMPTS_PER_PEER_WINDOW {
            let lease = limiter.reserve_at(peer(2), now);
            let Ok(lease) = lease else {
                panic!("attempt inside the peer window should be admitted");
            };
            drop(lease);
        }

        assert!(matches!(
            limiter.reserve_at(peer(2), now),
            Err(LanError::PeerLimitReached)
        ));
        assert!(
            limiter
                .reserve_at(peer(2), now + PEER_ATTEMPT_WINDOW)
                .is_ok()
        );
    }

    #[test]
    fn peer_table_has_a_fixed_entry_limit() {
        let limiter = PeerLimiter::default();
        let now = Instant::now();
        let mut leases = Vec::new();
        for number in 0..MAX_TRACKED_PEERS {
            let third = u8::try_from(number / 256)
                .unwrap_or_else(|_| panic!("test peer third octet should fit"));
            let fourth = u8::try_from(number % 256)
                .unwrap_or_else(|_| panic!("test peer fourth octet should fit"));
            let address = IpAddr::from([10, 1, third, fourth]);
            let lease = limiter.reserve_at(address, now);
            let Ok(lease) = lease else {
                panic!("peer table entry inside the limit should be admitted");
            };
            leases.push(lease);
        }

        assert!(matches!(
            limiter.reserve_at(IpAddr::from([10, 2, 0, 1]), now),
            Err(LanError::PeerLimitReached)
        ));
        drop(leases);
    }
}
