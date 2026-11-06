// Unit tests of the phrase helpers (install-i2). Pure functions and a real
// temporary directory; no tty and no daemon.

use std::io::Cursor;

use rand::SeedableRng;

use super::*;

const PHRASE: &str = "abandon ability able about above absent absorb abstract absurd abuse access \
                       accident account accuse achieve acid acoustic acquire across act action actor \
                       actress actual";

fn seeded() -> rand::rngs::StdRng {
    rand::rngs::StdRng::seed_from_u64(7)
}

#[test]
fn pick_positions_distinct_in_range() {
    let mut rng = seeded();
    for n in [1usize, 3, 24] {
        let got = pick_positions(&mut rng, n);
        assert_eq!(got.len(), n);
        assert!(got.iter().all(|p| (1..=24).contains(p)));
        let unique: std::collections::HashSet<_> = got.iter().collect();
        assert_eq!(unique.len(), n, "positions must be distinct: {got:?}");
        let mut sorted = got.clone();
        sorted.sort_unstable();
        assert_eq!(got, sorted, "positions are ascending");
    }
}

#[test]
fn pick_positions_more_than_24_is_clamped() {
    let got = pick_positions(&mut seeded(), 100);
    assert_eq!(got.len(), 24);
    assert_eq!(got, (1..=24).collect::<Vec<_>>());
}

#[test]
fn check_words_reports_first_wrong_position() {
    let words = PHRASE.split_whitespace().collect::<Vec<_>>();
    let answers = vec![
        (3usize, words[2].to_string()),
        (11, "definitely-wrong".to_string()),
        (20, "also-wrong".to_string()),
    ];
    assert_eq!(check_words(PHRASE, &answers), Err(11));
}

#[test]
fn check_words_normalizes_case_and_spaces() {
    let words = PHRASE.split_whitespace().collect::<Vec<_>>();
    let answers = vec![
        (3usize, format!("  {}  ", words[2].to_uppercase())),
        (11, format!("{}\t", words[10])),
        (20, format!("  {}", words[19])),
    ];
    assert_eq!(check_words(PHRASE, &answers), Ok(()));
    // Different case on the phrase side is normalized too.
    assert_eq!(
        check_words(&PHRASE.to_uppercase(), &answers),
        Ok(()),
        "the phrase on disk is compared case-insensitively"
    );
}

#[test]
fn check_words_names_a_position_outside_the_phrase() {
    let answers = vec![(25usize, "x".to_string())];
    assert_eq!(check_words(PHRASE, &answers), Err(25));
}

#[test]
fn mark_confirmed_atomic() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!is_confirmed(dir.path()));
    mark_confirmed(dir.path()).unwrap();
    assert!(is_confirmed(dir.path()));
    // Calling it again is fine and leaves no temporary files behind.
    mark_confirmed(dir.path()).unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
    assert_eq!(
        std::fs::read_to_string(confirmed_path(dir.path())).unwrap(),
        "checked\n"
    );
}

#[test]
fn format_grid_numbers_all_twenty_four_words() {
    let grid = format_grid(PHRASE);
    for n in 1..=24 {
        assert!(grid.contains(&format!("{n:>2}.")), "grid is missing {n}");
    }
    assert!(grid.ends_with('\n'));
}

/// Reading answers from a pipe: one word per line, no prompt needed.
#[test]
fn read_answers_from_stdin_lines() {
    let mut input = Cursor::new(b"  ABLE \nabout\n");
    let answers = read_answers(&mut input, &[2, 3], false, false).unwrap();
    assert_eq!(
        answers,
        vec![(2, "able".to_string()), (3, "about".to_string())]
    );
}

/// A short stdin is an error naming the position, never a silent pass.
#[test]
fn read_answers_short_stdin_fails() {
    let mut input = Cursor::new(b"able\n");
    let err = read_answers(&mut input, &[2, 3], false, false).unwrap_err();
    assert!(err.to_string().contains("word #3"), "{err}");
}
