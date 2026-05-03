use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[test]
fn restart_gate_first_call_triggers_returns_true() {
    let gate = RestartGate::new();
    let token = CancellationToken::new();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let r = gate.trigger_with(&token, move || {
        c.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    assert!(r);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(token.is_cancelled());
}

#[test]
fn restart_gate_second_call_returns_false_no_spawn() {
    let gate = RestartGate::new();
    let token = CancellationToken::new();
    let count = Arc::new(AtomicUsize::new(0));

    let c1 = count.clone();
    assert!(gate.trigger_with(&token, move || {
        c1.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }));

    let c2 = count.clone();
    assert!(!gate.trigger_with(&token, move || {
        c2.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }));

    assert_eq!(count.load(Ordering::SeqCst), 1, "spawn must not run twice");
}

#[test]
fn restart_gate_spawn_failure_still_marks_triggered_and_returns_true() {
    let gate = RestartGate::new();
    let token = CancellationToken::new();
    let r = gate.trigger_with(&token, || Err("synthetic".into()));
    assert!(r);
    // Shutdown token should NOT be cancelled when spawn fails — exiting without
    // a child would leave the user with no daemon at all.
    assert!(!token.is_cancelled());
    // Subsequent calls still return false (gate is consumed).
    assert!(!gate.trigger_with(&token, || Ok(())));
}

#[test]
fn restart_gate_concurrent_callers_only_one_wins() {
    use std::thread;
    let gate = Arc::new(RestartGate::new());
    let token = CancellationToken::new();
    let count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let g = gate.clone();
            let t = token.clone();
            let c = count.clone();
            thread::spawn(move || {
                g.trigger_with(&t, move || {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            })
        })
        .collect();

    let wins: usize = handles.into_iter().map(|h| h.join().unwrap() as usize).sum();
    assert_eq!(wins, 1);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(token.is_cancelled());
}
