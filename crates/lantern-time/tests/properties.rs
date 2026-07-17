// SPDX-License-Identifier: MPL-2.0

use std::time::Duration;

use lantern_time::{ClockError, ClockStatus, ClockTracker};
use proptest::{
    collection::vec,
    prelude::*,
    test_runner::{Config, RngAlgorithm, RngSeed},
};

fn config(seed: u64) -> Config {
    Config {
        cases: 128,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(seed),
        ..Config::default()
    }
}

proptest! {
    #![proptest_config(config(0x4c41_4e54_4552_4e11))]

    #[test]
    fn logical_time_never_moves_backwards(
        observations in vec((0_u16..=120, 900_000_u64..=1_100_000), 1..=256),
    ) {
        let tracker = ClockTracker::try_new(1_000_000);
        prop_assert!(tracker.is_ok());
        if let Ok(mut tracker) = tracker {
            let mut elapsed = 0_u64;
            let mut previous_logical = 1_000_000_u64;
            let mut previous_wall = 1_000_000_u64;

            for (elapsed_step, observed_wall) in observations {
                elapsed += u64::from(elapsed_step);
                let reading = tracker.observe(Duration::from_secs(elapsed), observed_wall);
                prop_assert!(reading.is_ok());
                if let Ok(reading) = reading {
                    prop_assert!(reading.wall_seconds() >= previous_logical);
                    let expected_status = if observed_wall < previous_wall {
                        ClockStatus::WallClockRollbackDetected
                    } else {
                        ClockStatus::Normal
                    };
                    prop_assert_eq!(reading.status(), expected_status);
                    prop_assert_eq!(
                        reading.status().requires_conservative_cleanup(),
                        expected_status == ClockStatus::WallClockRollbackDetected,
                    );
                    previous_logical = reading.wall_seconds();
                    previous_wall = observed_wall;
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(config(0x4c41_4e54_4552_4e12))]

    #[test]
    fn rejected_monotonic_regression_does_not_change_state(
        (first_elapsed, regressed_elapsed) in
            (1_u64..=10_000).prop_flat_map(|first| (Just(first), 0_u64..first)),
    ) {
        let tracker = ClockTracker::try_new(1_000_000);
        prop_assert!(tracker.is_ok());
        if let Ok(mut tracker) = tracker {
            let first = tracker.observe(
                Duration::from_secs(first_elapsed),
                1_000_000 + first_elapsed,
            );
            prop_assert!(first.is_ok());
            prop_assert_eq!(
                tracker.observe(
                    Duration::from_secs(regressed_elapsed),
                    1_000_001 + first_elapsed,
                ),
                Err(ClockError::MonotonicRegression),
            );
            let recovered = tracker.observe(
                Duration::from_secs(first_elapsed + 1),
                1_000_001 + first_elapsed,
            );
            prop_assert!(recovered.is_ok());
            if let Ok(recovered) = recovered {
                prop_assert_eq!(recovered.wall_seconds(), 1_000_001 + first_elapsed);
                prop_assert_eq!(recovered.status(), ClockStatus::Normal);
            }
        }
    }
}
