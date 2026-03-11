# Вопросы для ревью (утренний чеклист)

Здесь записаны некритичные вопросы и решения, принятые ночью автономно.

---

## Ночная сессия 2026-03-12: Phase 1 завершён

### Что сделано
1. **placement.rs** — 12 тестов, PlacementEngine (weighted selection w=trust², cap 6/partner, adaptive n, subnet diversity best-effort)
2. **budget.rs** — 15 тестов, BudgetPlanner (budget estimation, backup batch selection, disk pressure evaluation, eviction priority)
3. **Phase 1 GATE** — 22 интеграционных теста в `crates/syncback-core/tests/phase1_gate.rs`
4. **Итого:** 180 тестов (158 unit + 22 integration), все зелёные

### Решения, принятые автономно

1. **`rand = "0.8"` добавлен** в workspace deps и syncback-core deps (нужен для weighted sampling в placement)

2. **`BudgetRecord` расширен** — добавлено поле `weekly_stats: Vec<(u32, u32)>` с `#[serde(default)]` для backward compatibility. Нужно для rolling window placement success rate.

3. **`list_all_shards()` добавлен в Db** — нужен для budget estimation (подсчёт committed_gb). Аналогичен `list_all_peers()`.

4. **`tempfile` стал optional dep** — включается через `testutil` feature. Integration tests запускаются с `--features testutil`.

5. **Worktree подход не сработал** — worktree создаётся от master, а код не закоммичен → implementer agent переписал всё с нуля. Placement код был совместим и скопирован напрямую. Budget реализован без worktree.

### Вопросы (некритичные)

1. **Коммит?** Весь код Phase 1 (8 модулей, 180 тестов) до сих пор не закоммичен. Нужно закоммитить перед Phase 2.

2. **Warnings в placement/tests.rs** — пара unused import/variable warnings. Не критично, можно поправить при случае.

3. **ShardRecord.size_bytes** — в бюджетном модуле committed_gb считается как `unit.size_bytes / rs_n` потому что ShardRecord не имеет size_bytes поля. Точность достаточна для MVP, но если добавить size_bytes к ShardRecord — будет точнее.

4. **Wire-format ShardDescriptor** — TODO из прошлой сессии: переименовать wire-версию в messages.rs чтобы не путать с types.rs версией. Не блокер.
