// The 24-word recovery phrase: show it, check three words from the paper, and
// remember that the check passed (install-i2).
//
// The phrase is printed ONLY when stdout is a tty: an installer log, a CI
// capture or a redirected stdout must never hold it. It already lives in
// `identity.key` (0600), which is the one file that may: anyone who can read
// the friend's files can read the phrase (P5, said plainly in the docs).

#[cfg(test)]
mod tests;

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use rand::seq::index::sample;

use crate::daemon::identity::{KEYFILE_NAME, load_identity, normalize_phrase};

/// Written into the data directory after a successful phrase check; `setup`,
/// `phrase check`, `dr` and `init --mnemonic` all write it (install-i2).
pub const PHRASE_CONFIRMED_FILE: &str = "phrase-confirmed";

/// Number of positions asked at once.
pub const CHECK_POSITIONS: usize = 3;
/// Attempts before the grid is shown again.
pub const CHECK_ATTEMPTS: usize = 3;
/// Word count of a BIP39 recovery phrase.
pub const PHRASE_WORDS: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum PhraseError {
    #[error("no identity in this data directory: run 'viaticum setup' or 'viaticum init' first")]
    NotInitialized,
    #[error("the recovery phrase is only shown in a terminal; this output is not a tty")]
    NoTty,
    #[error("{0}")]
    Invalid(String),
    #[error("identity: {0}")]
    Identity(#[from] crate::daemon::identity::IdentityError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// `n` distinct 1-based positions in 1..=24, in ascending order.
pub fn pick_positions(rng: &mut impl rand::Rng, n: usize) -> Vec<usize> {
    let n = n.min(PHRASE_WORDS);
    let mut picked: Vec<usize> = sample(rng, PHRASE_WORDS, n)
        .into_iter()
        .map(|i| i + 1)
        .collect();
    picked.sort_unstable();
    picked
}

/// Check the answers against `mnemonic`. `Ok(())` when every answer matches;
/// `Err(position)` names the FIRST wrong position (1-based). Case and runs of
/// whitespace are ignored on both sides.
pub fn check_words(mnemonic: &str, answers: &[(usize, String)]) -> Result<(), usize> {
    let words: Vec<String> = normalize_phrase(mnemonic)
        .split_whitespace()
        .map(str::to_string)
        .collect();
    for (position, answer) in answers {
        let expected = position
            .checked_sub(1)
            .and_then(|i| words.get(i))
            .map(String::as_str);
        let got = normalize_phrase(answer);
        if expected != Some(got.as_str()) {
            return Err(*position);
        }
    }
    Ok(())
}

/// Write `<data_dir>/phrase-confirmed` atomically: a crash leaves either the
/// old state (no file) or the new one, never a half-written marker.
pub fn mark_confirmed(data_dir: &Path) -> io::Result<()> {
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let final_path = data_dir.join(PHRASE_CONFIRMED_FILE);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = data_dir.join(format!(
        ".{PHRASE_CONFIRMED_FILE}.tmp-{}-{stamp}",
        std::process::id()
    ));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(&tmp_path)?;
    file.write_all(b"checked\n")?;
    file.sync_all()?;
    drop(file);
    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

/// True when the phrase check passed for this data directory.
pub fn is_confirmed(data_dir: &Path) -> bool {
    data_dir.join(PHRASE_CONFIRMED_FILE).is_file()
}

/// A 6-column, 4-row numbered grid of the 24 words.
pub fn format_grid(mnemonic: &str) -> String {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let mut out = String::new();
    for row in 0..4 {
        for col in 0..6 {
            let i = row * 6 + col;
            match words.get(i) {
                Some(w) => out.push_str(&format!("{:>2}. {:<12}", i + 1, w)),
                None => out.push_str(&format!("{:>2}. {:<12}", i + 1, "—")),
            }
        }
        out.push('\n');
    }
    out
}

/// `viaticum phrase show`: print the phrase from `identity.key`, tty only.
pub fn run_show(data_dir: &Path) -> Result<(), PhraseError> {
    if !io::stdout().is_terminal() {
        return Err(PhraseError::NoTty);
    }
    let keyfile = load_keyfile(data_dir)?;
    println!("Your 24 recovery words (keep them on paper, never in a file):");
    print!("{}", format_grid(&keyfile.mnemonic));
    println!();
    println!("Check them later with: viaticum phrase check");
    Ok(())
}

/// `viaticum phrase check [--positions …] [--all]` (install-i2).
///
/// A tty asks three random positions (three attempts, then the grid again and a
/// new round). With stdin the answers are read line by line; `--positions` or
/// `--all` is then required because nobody can see a prompt in a pipe. Success
/// writes `phrase-confirmed`.
pub fn run_check(data_dir: &Path, positions: Vec<usize>, all: bool) -> Result<(), PhraseError> {
    let keyfile = load_keyfile(data_dir)?;
    if all && !positions.is_empty() {
        return Err(PhraseError::Invalid(
            "--all and --positions cannot be used together".into(),
        ));
    }
    let explicit = if all {
        Some((1..=PHRASE_WORDS).collect::<Vec<_>>())
    } else if positions.is_empty() {
        None
    } else {
        validate_positions(&positions)?;
        Some(positions)
    };

    let tty = crate::cli::is_interactive(io::stdin().is_terminal(), io::stdout().is_terminal());
    if tty {
        confirm_in_tty(&keyfile.mnemonic, explicit, None)?;
    } else {
        // In a pipe the caller must name the positions; otherwise print the
        // prompts to stderr so a human can still answer.
        let asked = explicit.unwrap_or_else(|| pick_positions(&mut rand::rng(), CHECK_POSITIONS));
        confirm_from_stdin(&keyfile.mnemonic, &asked)?;
    }
    mark_confirmed(data_dir)?;
    println!("Phrase confirmed.");
    Ok(())
}

/// The setup check: three random positions, three attempts, then the grid and a
/// new round. `positions` is `Some` only for tests and `--skip-phrase-check`
/// does not come here. The caller has already shown the grid and waited for
/// Enter.
pub fn confirm_in_tty(
    mnemonic: &str,
    explicit: Option<Vec<usize>>,
    max_rounds: Option<usize>,
) -> Result<(), PhraseError> {
    let mut round = 0usize;
    loop {
        round += 1;
        let positions = match &explicit {
            Some(p) => p.clone(),
            None => pick_positions(&mut rand::rng(), CHECK_POSITIONS),
        };
        let mut last_wrong = None;
        for attempt in 1..=CHECK_ATTEMPTS {
            let answers = ask_positions(&positions, attempt)?;
            match check_words(mnemonic, &answers) {
                Ok(()) => return Ok(()),
                Err(pos) => {
                    last_wrong = Some(pos);
                    let left = CHECK_ATTEMPTS - attempt;
                    if left > 0 {
                        eprintln!(
                            "Word #{pos} does not match. Try again ({left} {} left).",
                            if left == 1 { "try" } else { "tries" }
                        );
                    }
                }
            }
        }
        if let Some(limit) = max_rounds
            && round >= limit
        {
            let pos = last_wrong.unwrap_or(0);
            return Err(PhraseError::Invalid(format!(
                "the phrase did not match (word #{pos})"
            )));
        }
        println!();
        println!("That is not the phrase on your paper. Here are your words again:");
        print!("{}", format_grid(mnemonic));
        println!();
        wait_for_enter("Press Enter to check three words again: ")?;
    }
}

/// One round of answers from stdin (used without a tty).
pub fn confirm_from_stdin(mnemonic: &str, positions: &[usize]) -> Result<(), PhraseError> {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let answers = read_answers(&mut stdin, positions, true, false)?;
    check_words(mnemonic, &answers).map_err(|pos| {
        PhraseError::Invalid(format!("word #{pos} does not match the recovery phrase"))
    })
}

/// Answer lines from `reader`, with prompts when `prompt` is true. In a pipe
/// the prompts go to stderr so stdout stays clean (aside from the final line).
pub fn read_answers(
    reader: &mut impl BufRead,
    positions: &[usize],
    prompt: bool,
    _interactive: bool,
) -> Result<Vec<(usize, String)>, PhraseError> {
    let mut answers = Vec::with_capacity(positions.len());
    for &position in positions {
        if prompt {
            eprint!("Word #{position}? ");
            io::stderr().flush()?;
        }
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err(PhraseError::Invalid(format!(
                "no answer for word #{position}"
            )));
        }
        let got = normalize_phrase(&line);
        if got.is_empty() {
            return Err(PhraseError::Invalid(format!(
                "empty answer for word #{position}"
            )));
        }
        answers.push((position, got));
    }
    Ok(answers)
}

fn ask_positions(
    positions: &[usize],
    _attempt: usize,
) -> Result<Vec<(usize, String)>, PhraseError> {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut answers = Vec::with_capacity(positions.len());
    for &position in positions {
        loop {
            print!("Word #{position}? ");
            io::stdout().flush()?;
            match read_answer_line(&mut stdin)? {
                AnswerLine::Word(word) => {
                    answers.push((position, word));
                    break;
                }
                // An empty Enter is a failed answer, not an abort: ask the
                // same word again (NOTE 5). It does not use up one of the
                // three attempts.
                AnswerLine::Empty => println!("Please type word #{position}."),
                AnswerLine::Eof => {
                    return Err(PhraseError::Invalid(format!(
                        "no answer for word #{position}"
                    )));
                }
            }
        }
    }
    Ok(answers)
}

/// One line from the terminal for a phrase word. `Empty` means "ask again";
/// only end of input aborts.
enum AnswerLine {
    Word(String),
    Empty,
    Eof,
}

fn read_answer_line(reader: &mut impl BufRead) -> io::Result<AnswerLine> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(AnswerLine::Eof);
    }
    let got = normalize_phrase(&line);
    if got.is_empty() {
        Ok(AnswerLine::Empty)
    } else {
        Ok(AnswerLine::Word(got))
    }
}

fn wait_for_enter(prompt: &str) -> Result<(), PhraseError> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(())
}

fn validate_positions(positions: &[usize]) -> Result<(), PhraseError> {
    if positions.is_empty() {
        return Err(PhraseError::Invalid("no positions given".into()));
    }
    let mut seen = std::collections::HashSet::new();
    for &p in positions {
        if !(1..=PHRASE_WORDS).contains(&p) {
            return Err(PhraseError::Invalid(format!(
                "position {p} is outside 1..={PHRASE_WORDS}"
            )));
        }
        if !seen.insert(p) {
            return Err(PhraseError::Invalid(format!("position {p} is repeated")));
        }
    }
    Ok(())
}

fn load_keyfile(data_dir: &Path) -> Result<crate::daemon::identity::IdentityKeyFile, PhraseError> {
    if !data_dir.join(KEYFILE_NAME).is_file() {
        return Err(PhraseError::NotInitialized);
    }
    Ok(load_identity(data_dir)?)
}

/// The path of `phrase-confirmed` (for callers that only need the path).
pub fn confirmed_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PHRASE_CONFIRMED_FILE)
}
