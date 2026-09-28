use tempfile::TempDir;

use crate::db::Db;
use crate::types::{FourRPhaseRecord, Timestamp};

/// DB-1: no row reads as released; a written latch survives closing and reopening the file.
#[test]
fn four_r_phase_defaults_to_released_and_survives_reopening_the_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("db.redb");
    {
        let db = Db::open(&path).unwrap();
        assert_eq!(db.get_four_r_phase().unwrap(), FourRPhaseRecord::default());
        assert!(!db.get_four_r_phase().unwrap().evicting);
        db.set_four_r_phase(&FourRPhaseRecord {
            evicting: true,
            since: Some(Timestamp(1_700_000_000)),
        })
        .unwrap();
    }
    let db = Db::open(&path).unwrap();
    assert_eq!(
        db.get_four_r_phase().unwrap(),
        FourRPhaseRecord {
            evicting: true,
            since: Some(Timestamp(1_700_000_000)),
        }
    );
    db.set_four_r_phase(&FourRPhaseRecord {
        evicting: false,
        since: Some(Timestamp(1_700_000_060)),
    })
    .unwrap();
    assert!(!db.get_four_r_phase().unwrap().evicting);
}

/// DB-2: a row that does not decode is an error, never a silent "released".
#[test]
fn a_corrupt_phase_row_is_an_error_not_a_default() {
    let db = Db::open_in_memory().unwrap();
    db.put_raw_four_r_phase_for_test(&[0xFF, 0x00, 0x13])
        .unwrap();
    assert!(db.get_four_r_phase().is_err());
}
