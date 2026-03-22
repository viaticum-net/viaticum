# Phase 3 GATE Tests — Task Spec

**Цель:** три smoke/integration теста, которые докажут что полная система работает
end-to-end. Запускаются через `cargo test -p syncback -- --test-threads=1 phase3`.

**Ограничение:** эти тесты медленные (секунды). Помечать `#[ignore]` НЕ нужно —
они входят в GATE и должны проходить при каждом `cargo test -p syncback`.

---

## Расположение файлов

```
crates/syncback/tests/
  phase3_gate.rs          ← основной файл (subprocess + tmpdir варианты)

tests/docker/             ← корень проекта
  docker-compose.yml      ← два daemon-контейнера
  node_a/
    Dockerfile
    config.toml
  node_b/
    Dockerfile
    config.toml
  run_tests.sh            ← запускает docker compose, ждёт, проверяет, сообщает
```

---

## Зависимости модулей

- `crate::cli::init::init_with_mnemonic` — уже реализована, создаёт `~/.syncback/`
  без интерактивного ввода (принимает `&[&str]`)
- `crate::daemon::{Config, DaemonHandle}` — уже реализован, `DaemonHandle::start(config).await`
- `crate::cli::send_request` + `crate::daemon::cli_server::{CliRequest, CliResponse, StatusPayload}`
- `crate::daemon::processor::run` — уже реализован

---

## Тест 1: `daemon_starts_and_responds_to_status`

### Что тестируем

Запускаем реальный daemon через `DaemonHandle::start()` (не subprocess, не binary),
отправляем `Status` через Unix socket, проверяем ответ.

### Почему не subprocess

`DaemonHandle::start()` уже поднимает все 5 tokio tasks в текущем async runtime.
Это быстрее и требует меньше настройки, чем subprocess. Subprocess нужен только
для теста 3 (`full_backup_restore_from_seed`), где требуется честный `syncback init`.

### Сигнатура

```rust
#[tokio::test]
async fn daemon_starts_and_responds_to_status() { ... }
```

### Шаги

1. Создать `TempDir` — это будет `syncback_dir`.
2. Вызвать `init_with_mnemonic(dir.path(), &FIXED_TEST_MNEMONIC)`.
3. Собрать `Config` с `syncback_dir = dir.path()` (остальные поля — defaults).
4. `DaemonHandle::start(config).await.expect("daemon start")`.
5. Подождать 200 мс — socket должен появиться.
6. Retry loop: открыть `UnixStream` к `dir.path().join("syncback.sock")`.
   Retry 10 раз с интервалом 100 мс. Если не подключился — `panic!`.
7. Отправить JSON строку `{"cmd":"status"}\n`, прочитать ответ (одна строка).
8. Разобрать `CliResponse`. Проверить что это `CliResponse::StatusOk(...)`.
9. Проверить инварианты `StatusPayload`:
   - `uptime_secs < 10` (daemon только что стартовал)
   - `peer_count == 0` (нет seed nodes в конфиге)
   - `dirty_files == 0` (нет include-папок)
10. `handle.shutdown().await.expect("shutdown")`.

### Helper: `wait_for_socket`

```rust
async fn wait_for_socket(path: &std::path::Path) -> tokio::net::UnixStream {
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Ok(s) = tokio::net::UnixStream::connect(path).await {
            return s;
        }
    }
    panic!("socket not ready after 2s: {:?}", path)
}
```

### Helper: `send_cli_request_raw`

```rust
/// Отправляет один JSON-запрос через UnixStream, возвращает десериализованный CliResponse.
async fn send_cli_request_raw(
    path: &std::path::Path,
    request: &crate::daemon::cli_server::CliRequest,
) -> crate::daemon::cli_server::CliResponse {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .expect("connect to socket");
    let json = serde_json::to_string(request).unwrap();
    let (read_half, mut write_half) = stream.split();
    write_half.write_all(format!("{json}\n").as_bytes()).await.unwrap();
    write_half.flush().await.unwrap();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).expect("parse CliResponse")
}
```

### Константа для теста

```rust
/// BIP39 мнемоника фиксирована — используется во всех тестах.
/// Сгенерирована заранее, checksum верный.
const TEST_MNEMONIC: &[&str] = &[
    "witch", "collapse", "practice", "feed", "shame", "open",
    "despair", "creek", "road", "again", "ice", "least",
    "toward", "erupt", "burst", "wolf", "high", "option",
    "zebra", "brown", "hybrid", "weapon", "swamp", "cousin",
];
```

DECISION NEEDED: нужно сгенерировать валидную 24-словную BIP39 мнемонику с правильной
контрольной суммой и вставить её как константу. Способ: вызвать
`bip39::Mnemonic::from_entropy(&[0u8; 32])` в тесте-хелпере и сохранить результат.
Либо взять любые 24 BIP39 слова с правильным checksum.
Рекомендую: в `testutil` написать функцию `fixed_test_mnemonic() -> Vec<String>`,
которая генерирует по детерминированному entropy `[0u8; 32]`.

### Ожидаемый результат

Тест проходит за < 3 секунды. Не зависит от сети.

---

## Тест 2: `two_daemons_connect_and_see_each_other`

### Что тестируем

Два daemon'а на одной машине реально соединяются через ConnectPeer
и каждый видит другого в списке peers (peer_count >= 1).

### Сигнатура

```rust
#[tokio::test]
async fn two_daemons_connect_and_see_each_other() { ... }
```

### Шаги

1. Создать два `TempDir` — `dir_a` и `dir_b`.
2. `init_with_mnemonic(dir_a.path(), &mnemonic_a)` и `init_with_mnemonic(dir_b.path(), &mnemonic_b)`.
   Использовать разные мнемоники (entropy `[0u8; 32]` и `[1u8; 32]`).
3. Собрать `config_a` и `config_b` с разными `syncback_dir`.
4. Стартовать оба daemon'а.
5. Дождаться socket'ов обоих daemon'ов (`wait_for_socket`).
6. Получить `node_addr` daemon'а B через `Status` ответ (`StatusPayload.own_node_id`).
7. Отправить daemon'у A команду `ConnectPeer { node_addr: node_addr_b }`.
8. Подождать 500 мс.
9. Проверить `Status` daemon'а A: `peer_count >= 1`.
10. Завершить оба daemon'а.

### РЕШЕНО:
- `own_node_id: String` добавляется в `StatusPayload` (полный EndpointAddr как строка)
- `CliRequest::ConnectPeer { node_addr: String }` добавляется — полезно и для UX
- `ConnectAddr` в network task реализуется (реальный `endpoint.connect()`)

### Тайминг

Тест должен завершиться за < 5 секунд.

---

## Тест 3: `full_backup_restore_from_seed`

### Что тестируем

Полный pipeline: создание файлов → backup → шарды у holder'а → restore из seed phrase.
Node C имеет ту же identity что A (та же мнемоника) + **копию DB** (чтобы знать shard map).
Полный DR без DB — Phase 4.

### Подход: DB copy (variant C)

Node A делает backup, потом останавливается. DB копируется из dir_a в dir_c.
Node C стартует с той же мнемоникой + скопированной DB. Делает restore.
Это проверяет полный pipeline: encrypt → erasure → upload → download → RS decode → decrypt.

### Передача шардов: DirectMessage inline

iroh-blobs не реализован (Phase 4). Шарды передаются inline через
`DirectBody::ShardData { shard_id, data }`. Размер ~1-3 МБ, QUIC справится.

---

### 3a. In-process вариант

#### Сигнатура

```rust
#[tokio::test]
#[timeout(60_000)] // 60 секунд максимум
async fn full_backup_restore_from_seed_inprocess() { ... }
```

Для таймаута использовать `tokio::time::timeout`:

```rust
tokio::time::timeout(
    std::time::Duration::from_secs(60),
    run_full_backup_restore(),
)
.await
.expect("test timed out after 60s")
.expect("test failed");
```

#### Подготовка тестовых файлов

```rust
fn create_test_files(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    // Набор тестовых файлов разного размера и структуры.
    // Вложенные директории, UTF-8 пути, бинарный контент.
    let files = vec![
        ("docs/notes.txt",   b"hello from syncback test\n".repeat(100).into_bytes()),
        ("docs/config.json", br#"{"key": "value", "n": 42}"#.to_vec()),
        ("photos/img_001.bin", vec![0xABu8; 4096]),
        ("photos/img_002.bin", (0u8..=255).cycle().take(8192).collect()),
        ("large/data.bin",   vec![0x55u8; 64 * 1024]), // 64 KiB
    ];
    let mut result = Vec::new();
    for (rel_path, content) in files {
        let full_path = dir.join(rel_path);
        std::fs::create_dir_all(full_path.parent().unwrap()).unwrap();
        std::fs::write(&full_path, &content).unwrap();
        result.push((full_path, content));
    }
    result
}
```

#### Полный flow теста

```rust
async fn run_full_backup_restore() -> anyhow::Result<()> {
    // ── Шаг 1: Подготовить директории ──
    let root = tempfile::TempDir::new()?;
    let files_dir   = root.path().join("files");
    let dir_a       = root.path().join("node_a");
    let dir_b       = root.path().join("node_b");
    let dir_c       = root.path().join("node_c");
    let restore_dir = root.path().join("restored");
    std::fs::create_dir_all(&files_dir)?;
    std::fs::create_dir_all(&restore_dir)?;

    // ── Шаг 2: Создать тестовые файлы ──
    let test_files = create_test_files(&files_dir);

    // ── Шаг 3: Инициализировать node A ──
    let mnemonic_a = fixed_test_mnemonic_a(); // [0u8; 32] entropy → 24 words
    std::fs::create_dir_all(&dir_a)?;
    let key_file_a = crate::cli::init::init_with_mnemonic(&dir_a, &mnemonic_a)?;
    // key_file_a.identity_pub будет использован node B для allowlist

    // ── Шаг 4: Инициализировать node B (holder) ──
    let mnemonic_b = fixed_test_mnemonic_b(); // [1u8; 32] entropy → 24 words
    std::fs::create_dir_all(&dir_b)?;
    let _key_file_b = crate::cli::init::init_with_mnemonic(&dir_b, &mnemonic_b)?;

    // ── Шаг 5: Стартовать daemon B (holder) с quota ──
    let config_b = Config {
        syncback_dir: dir_b.clone(),
        storage: StorageConfig { quota_gb: 10 },
        backup: BackupConfig { include: vec![], exclude: vec![] },
        // ... остальное default
        ..Config::default()
    };
    // Переопределить syncback_dir после default():
    let config_b = Config { syncback_dir: dir_b.clone(), ..Config::default() };
    let handle_b = DaemonHandle::start(config_b).await?;
    let sock_b = dir_b.join("syncback.sock");
    wait_for_socket(&sock_b).await;

    // ── Шаг 6: Стартовать daemon A (owner) ──
    // Config A: backup включает files_dir с importance=0.9
    let config_a = Config {
        syncback_dir: dir_a.clone(),
        backup: BackupConfig {
            include: vec![IncludeEntry {
                path: files_dir.clone(),
                importance: 0.9,
            }],
            exclude: vec![],
        },
        storage: StorageConfig { quota_gb: 1 },
        ..Config::default()
    };
    let handle_a = DaemonHandle::start(config_a).await?;
    let sock_a = dir_a.join("syncback.sock");
    wait_for_socket(&sock_a).await;

    // ── Шаг 7: Связать A и B (connect peers) ──
    // РЕШЕНО: используем ConnectPeer CLI команду + own_node_id в StatusPayload.
    connect_peers(&sock_a, &get_node_addr(&sock_b).await).await?;

    // ── Шаг 8: Запустить backup на A ──
    let backup_resp = send_cli_request_raw(&sock_a, &CliRequest::BackupNow).await;
    assert!(matches!(backup_resp, CliResponse::Ok { .. } | CliResponse::Accepted { .. }));

    // ── Шаг 9: Дождаться размещения шардов ──
    // Ждём до 30 секунд, проверяем каждые 500 мс:
    // Status daemon A: shards_placed > 0.
    wait_for_shards_placed(&sock_a, 1, Duration::from_secs(30)).await?;

    // ── Шаг 10: Остановить node A, скопировать DB в dir_c ──
    handle_a.shutdown().await?;
    // Копируем syncback_dir A → C (DB + identity.key).
    // Node C = та же identity (seed phrase) + та же DB (знает shard map).
    // Полный DR без DB = Phase 4.
    copy_dir_recursive(&dir_a, &dir_c)?;
    // Удалить оригинальные файлы — node C будет восстанавливать их.
    std::fs::remove_dir_all(&files_dir)?;

    // ── Шаг 11: Стартовать daemon C (та же identity + DB) ──
    let config_c = Config {
        syncback_dir: dir_c.clone(),
        backup: BackupConfig { include: vec![], exclude: vec![] },
        storage: StorageConfig { quota_gb: 1 },
        ..Config::default()
    };
    let handle_c = DaemonHandle::start(config_c).await?;
    let sock_c = dir_c.join("syncback.sock");
    wait_for_socket(&sock_c).await;

    // ── Шаг 12: Подключить C к B ──
    connect_peers(&sock_c, &get_node_addr(&sock_b).await).await?;

    // ── Шаг 13: Запустить restore на C ──
    // DB intact → node C знает file→unit→shard mapping.
    let original_path = files_dir.join("docs/notes.txt");
    let dest_path = restore_dir.join("notes_restored.txt");
    let restore_resp = send_cli_request_raw(
        &sock_c,
        &CliRequest::RestoreFile {
            path: original_path.to_str().unwrap().to_string(),
            dest: dest_path.to_str().unwrap().to_string(),
        },
    ).await;
    assert!(matches!(restore_resp, CliResponse::Ok { .. } | CliResponse::Accepted { .. }));

    // ── Шаг 14: Дождаться восстановления файла ──
    wait_for_file(&dest_path, Duration::from_secs(30)).await?;

    // ── Шаг 15: Верифицировать байт-в-байт ──
    let restored = std::fs::read(&dest_path)?;
    let original_content = b"hello from syncback test\n".repeat(100).into_bytes();
    assert_eq!(
        restored, original_content,
        "restored file must match original byte-for-byte"
    );

    // ── Шаг 16: Корректное завершение ──
    handle_b.shutdown().await?;
    handle_c.shutdown().await?;

    Ok(())
}
```

#### Helper: `wait_for_shards_placed`

```rust
/// Ждёт пока daemon (через socket) сообщит shards_placed >= min_shards.
/// Опрашивает каждые 500 мс. Паникует по истечению таймаута.
async fn wait_for_shards_placed(
    socket: &std::path::Path,
    min_shards: usize,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("timeout waiting for shards_placed >= {min_shards}");
        }
        let resp = send_cli_request_raw(socket, &CliRequest::Status).await;
        if let CliResponse::StatusOk(s) = resp {
            if s.shards_placed >= min_shards {
                return Ok(());
            }
            tracing::debug!(shards_placed = s.shards_placed, "waiting for shards...");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
```

#### Helper: `wait_for_file`

```rust
/// Ждёт появления файла по пути. Паникует по истечению таймаута.
async fn wait_for_file(
    path: &std::path::Path,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("timeout waiting for file: {:?}", path);
        }
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}
```

#### Helper: `connect_peers`

```rust
/// Отправляет daemon'у команду подключиться к peer по node_addr строке.
/// Требует реализации CliRequest::ConnectPeer (см. DECISION NEEDED в тесте 2).
async fn connect_peers(socket: &std::path::Path, node_addr: &str) -> anyhow::Result<()> {
    let resp = send_cli_request_raw(
        socket,
        &CliRequest::ConnectPeer { node_addr: node_addr.to_string() },
    ).await;
    match resp {
        CliResponse::Ok { .. } | CliResponse::Accepted { .. } => Ok(()),
        CliResponse::Error { message } => anyhow::bail!("connect failed: {message}"),
        other => anyhow::bail!("unexpected: {other:?}"),
    }
}
```

#### Helper: `get_node_addr`

```rust
/// Получает строковый node_addr daemon'а через Status.
/// Требует поля `own_node_id: String` в StatusPayload.
async fn get_node_addr(socket: &std::path::Path) -> String {
    let resp = send_cli_request_raw(socket, &CliRequest::Status).await;
    match resp {
        CliResponse::StatusOk(s) => s.own_node_id,
        other => panic!("expected StatusOk, got {other:?}"),
    }
}
```

#### Helper: `fixed_test_mnemonic_a` / `fixed_test_mnemonic_b`

```rust
/// Детерминированная мнемоника для node A (entropy = [0u8; 32]).
fn fixed_test_mnemonic_a() -> Vec<String> {
    use bip39::Mnemonic;
    let entropy = [0u8; 32];
    let m = Mnemonic::from_entropy(&entropy).unwrap();
    m.words().map(|s| s.to_string()).collect()
}

/// Детерминированная мнемоника для node B (entropy = [1u8; 32]).
fn fixed_test_mnemonic_b() -> Vec<String> {
    use bip39::Mnemonic;
    let entropy = [1u8; 32];
    let m = Mnemonic::from_entropy(&entropy).unwrap();
    m.words().map(|s| s.to_string()).collect()
}
```

---

### 3b. Subprocess + Docker вариант

#### Структура `tests/docker/`

```
tests/docker/
  README.md              — инструкция запуска
  docker-compose.yml     — два сервиса: node_a, node_b
  node_a/
    Dockerfile
    config.toml          — include = ["/data"], quota_gb = 10
    entrypoint.sh        — syncback init (non-interactive) + syncback daemon
  node_b/
    Dockerfile
    config.toml          — include = [], quota_gb = 20
    entrypoint.sh
  run_tests.sh           — оркестратор
  verify_restore.sh      — сравнивает файлы
```

#### `docker-compose.yml`

```yaml
version: "3.9"

services:
  node_b:
    build: ./node_b
    container_name: syncback_node_b
    environment:
      - SYNCBACK_DIR=/syncback
      - RUST_LOG=syncback=info,iroh=warn
    volumes:
      - node_b_data:/syncback
    networks:
      - syncback_net
    healthcheck:
      test: ["CMD", "sh", "-c", "echo '{\"cmd\":\"status\"}' | socat - UNIX-CONNECT:/syncback/syncback.sock"]
      interval: 5s
      timeout: 5s
      retries: 10

  node_a:
    build: ./node_a
    container_name: syncback_node_a
    depends_on:
      node_b:
        condition: service_healthy
    environment:
      - SYNCBACK_DIR=/syncback
      - RUST_LOG=syncback=info,iroh=warn
      - PEER_B_ADDR=${NODE_B_ADDR}  # передаётся из run_tests.sh
    volumes:
      - node_a_data:/syncback
      - ./test_files:/data:ro
    networks:
      - syncback_net

volumes:
  node_a_data:
  node_b_data:

networks:
  syncback_net:
    driver: bridge
```

#### `node_b/Dockerfile`

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*
COPY target/release/syncback /usr/local/bin/syncback
COPY node_b/config.toml /tmp/config_template.toml
COPY node_b/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV SYNCBACK_DIR=/syncback
ENTRYPOINT ["/entrypoint.sh"]
```

#### `node_b/entrypoint.sh`

```bash
#!/bin/sh
set -e

# Non-interactive init: entropy from env or fixed.
# syncback init требует ввода пользователя — используем init_with_mnemonic через специальную
# CLI команду или direct env var.
# OPTION: добавить `syncback init --non-interactive --mnemonic "word1 word2..."` флаг.
# Пока: использовать фиксированный identity.key (pre-generated и скопированный в образ).

if [ ! -f "$SYNCBACK_DIR/identity.key" ]; then
    mkdir -p "$SYNCBACK_DIR"
    # identity.key для node B — скопирован при сборке образа.
    cp /tmp/identity_b.key "$SYNCBACK_DIR/identity.key"
    cp /tmp/config_template.toml "$SYNCBACK_DIR/config.toml"
fi

exec syncback daemon
```

#### `run_tests.sh`

```bash
#!/bin/bash
# Phase 3 GATE: Docker smoke test
# Запускать из корня проекта после `cargo build --release`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKER_DIR="$SCRIPT_DIR"

echo "=== Phase 3 GATE: Docker smoke test ==="

# 1. Собрать бинарник.
cargo build --release -p syncback 2>&1 | tail -5
cp "$PROJECT_ROOT/target/release/syncback" "$DOCKER_DIR/"

# 2. Создать тестовые файлы.
mkdir -p "$DOCKER_DIR/test_files/docs"
echo "hello from docker gate test" > "$DOCKER_DIR/test_files/docs/hello.txt"
dd if=/dev/urandom bs=4096 count=10 > "$DOCKER_DIR/test_files/docs/random.bin" 2>/dev/null

# 3. Запустить docker compose.
docker compose -f "$DOCKER_DIR/docker-compose.yml" up -d node_b

# 4. Дождаться node_b healthcheck.
echo "Waiting for node_b to be healthy..."
for i in $(seq 1 30); do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' syncback_node_b 2>/dev/null || echo "starting")
    if [ "$STATUS" = "healthy" ]; then
        echo "node_b healthy after ${i}x5s"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: node_b not healthy after 150s"
        docker compose -f "$DOCKER_DIR/docker-compose.yml" logs node_b | tail -50
        exit 1
    fi
    sleep 5
done

# 5. Получить node_addr node_b.
NODE_B_ADDR=$(docker exec syncback_node_b sh -c \
    'echo "{\"cmd\":\"status\"}" | socat - UNIX-CONNECT:/syncback/syncback.sock' \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("own_node_id",""))' \
    2>/dev/null || echo "")
echo "node_b addr: $NODE_B_ADDR"

# 6. Запустить node_a с адресом B.
export NODE_B_ADDR
docker compose -f "$DOCKER_DIR/docker-compose.yml" up -d node_a

# 7. Дождаться backup completion на node_a.
echo "Waiting for backup to complete..."
for i in $(seq 1 60); do
    SHARDS=$(docker exec syncback_node_a sh -c \
        'echo "{\"cmd\":\"status\"}" | socat - UNIX-CONNECT:/syncback/syncback.sock' \
        | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("shards_placed",0))' \
        2>/dev/null || echo "0")
    if [ "$SHARDS" -gt 0 ]; then
        echo "node_a placed $SHARDS shards after ${i}x5s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: no shards placed after 300s"
        docker compose -f "$DOCKER_DIR/docker-compose.yml" logs node_a | tail -50
        exit 1
    fi
    sleep 5
done

# 8. Уничтожить node_a (симуляция потери устройства).
echo "Destroying node_a (simulating device loss)..."
docker compose -f "$DOCKER_DIR/docker-compose.yml" stop node_a
docker compose -f "$DOCKER_DIR/docker-compose.yml" rm -f node_a
docker volume rm syncback_node_a_data || true

# 9. Запустить node_c с той же мнемоникой что A.
# (node_c — это node_a с тем же identity.key, другие данные)
# Для simplicity: rebuild образа node_a, он использует тот же identity.key
docker compose -f "$DOCKER_DIR/docker-compose.yml" up -d node_a

# 10. Запустить restore.
RESTORE_DEST="/tmp/restored_hello.txt"
docker exec syncback_node_a sh -c \
    "echo '{\"cmd\":\"restore_file\",\"path\":\"/data/docs/hello.txt\",\"dest\":\"$RESTORE_DEST\"}' \
    | socat - UNIX-CONNECT:/syncback/syncback.sock"

# 11. Дождаться файла.
echo "Waiting for restore..."
for i in $(seq 1 60); do
    if docker exec syncback_node_a test -f "$RESTORE_DEST"; then
        echo "File restored after ${i}x5s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: restore not completed after 300s"
        exit 1
    fi
    sleep 5
done

# 12. Верифицировать.
ORIGINAL="hello from docker gate test"
RESTORED=$(docker exec syncback_node_a cat "$RESTORE_DEST")
if [ "$ORIGINAL" = "$RESTORED" ]; then
    echo "=== GATE PASSED: restored file matches original ==="
else
    echo "ERROR: content mismatch!"
    echo "  expected: $ORIGINAL"
    echo "  got:      $RESTORED"
    exit 1
fi

# 13. Cleanup.
docker compose -f "$DOCKER_DIR/docker-compose.yml" down -v
echo "=== Phase 3 GATE: Docker test COMPLETE ==="
```

---

## Изменения в существующем коде

Для того чтобы Gate тесты работали, нужны минимальные изменения в уже реализованных модулях:

### 1. `StatusPayload` — добавить `own_node_id`

В `crates/syncback/src/daemon/cli_server/mod.rs`:

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct StatusPayload {
    pub uptime_secs: u64,
    pub peer_count: usize,
    pub shards_held: usize,
    pub shards_placed: usize,
    pub budget_gb: f64,
    pub dirty_files: usize,
    // НОВОЕ: строковое представление NodeId (hex), нужно для тестов
    pub own_node_id: String,
}
```

В `StatusReply` (`daemon/mod.rs`) добавить `own_node_id: String`.
В `processor.rs` при ответе на `CliCmd::Status` — передавать `NodeId` из `NetworkHandle`.

### 2. `CliRequest::ConnectPeer` — новая команда

В `crates/syncback/src/daemon/cli_server/mod.rs`:

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum CliRequest {
    Status,
    BackupNow,
    RestoreFile { path: String, dest: String },
    Peers,
    Shutdown,
    // НОВОЕ: подключиться к peer по node_addr строке
    ConnectPeer { node_addr: String },
}
```

В `processor.rs` обработать `CliCmd::ConnectPeer { node_addr }`:
отправить `NetCommand::ConnectAddr { node_addr }` в network task.

В `daemon/mod.rs` добавить:
```rust
pub enum CliCmd {
    // ...существующие...
    ConnectPeer { node_addr: String },
}
```

### 3. `DirectBody::ShardData` — inline передача шардов

В `crates/syncback-core/src/messages/mod.rs` добавить:

```rust
pub enum DirectBody {
    // ...существующие...
    ShardData(ShardDataMsg),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDataMsg {
    pub shard_id: ShardId,
    pub data: Vec<u8>,
}
```

Holder при получении `RestoreRequest` → читает шард → отправляет `ShardData` обратно.
Owner при получении `ShardData` → сохраняет для RS decode.

### 4. `handle_cli_restore` — реальная реализация

В `processor.rs` заменить заглушку:

```rust
async fn handle_cli_restore(&self, path: PathBuf, dest: PathBuf, reply: ...) {
    // 1. Найти FileRecord по path в DB
    // 2. Найти UnitRecord по file.current_unit_id
    // 3. Получить список ShardRecord для unit (list_shards_for_unit)
    // 4. Выбрать k шардов со статусом Stored
    // 5. Для каждого: NetCommand::SendDirect(RestoreRequest { shard_id }) к holder'у
    // 6. Собрать ShardData ответы (через NetEvent::MessageReceived)
    // 7. RS decode (k из n шардов → plaintext)
    // 8. Decrypt (ChaCha20-Poly1305 с unit key)
    // 9. Записать файл в dest
    // 10. reply.send(Ok(...))
}
```

### 5. `ConnectAddr` — реальная реализация в network

В `network/mod.rs` заменить заглушку:

```rust
NetCommand::ConnectAddr { node_addr } => {
    // 1. EndpointAddr::from_str(&node_addr)
    // 2. endpoint.connect(addr, ALPN).await
    // 3. Выполнить handshake (send_our_handshake + read_their_handshake)
    // 4. Emit NetEvent::PeerConnected
    // 5. Запустить handle_incoming() для нового connection
}
```

### 6. `Config` — кастомный `syncback_dir`

Уже работает — поле публичное, тест создаёт Config через struct literal.

---

## Файл тестов: полная структура

```rust
// crates/syncback/tests/phase3_gate.rs

//! Phase 3 GATE tests.
//!
//! Три теста, доказывающие что полная система работает end-to-end.
//! Медленные (секунды), но не #[ignore] — входят в обязательный GATE.
//!
//! Запуск: cargo test -p syncback phase3 -- --test-threads=1

use std::time::Duration;

use syncback::cli::init::init_with_mnemonic;
use syncback::daemon::{BackupConfig, Config, DaemonHandle, IncludeEntry, NetworkConfig,
                       ScheduleConfig, StorageConfig, SyncFrequency, VacuumFrequency};
use syncback::daemon::cli_server::{CliRequest, CliResponse};

// ── Helpers ──────────────────────────────────────────────────────────────────

async fn wait_for_socket(path: &std::path::Path) -> tokio::net::UnixStream { ... }
async fn send_cli_request_raw(path: &std::path::Path, req: &CliRequest) -> CliResponse { ... }
async fn wait_for_shards_placed(socket: &std::path::Path, min: usize, timeout: Duration) -> anyhow::Result<()> { ... }
async fn wait_for_file(path: &std::path::Path, timeout: Duration) -> anyhow::Result<()> { ... }
async fn connect_peers(socket: &std::path::Path, node_addr: &str) -> anyhow::Result<()> { ... }
async fn get_node_addr(socket: &std::path::Path) -> String { ... }
fn create_test_files(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> { ... }
fn fixed_test_mnemonic_a() -> Vec<String> { ... }  // entropy [0u8; 32]
fn fixed_test_mnemonic_b() -> Vec<String> { ... }  // entropy [1u8; 32]
fn make_config(syncback_dir: std::path::PathBuf, include: Vec<IncludeEntry>) -> Config { ... }

// ── Test 1 ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn daemon_starts_and_responds_to_status() { ... }

// ── Test 2 ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn two_daemons_start_independently_and_respond() { ... }

// ── Test 3 ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn full_backup_restore_from_seed_inprocess() {
    tokio::time::timeout(
        Duration::from_secs(120),
        run_full_backup_restore(),
    )
    .await
    .expect("test timed out")
    .expect("test failed");
}

async fn run_full_backup_restore() -> anyhow::Result<()> { ... }
```

---

## Важные edge cases и ограничения

### Изоляция тестов

Каждый тест создаёт собственный `TempDir`. Socket пути не пересекаются.
Тесты должны запускаться с `--test-threads=1` чтобы не конкурировать за порты iroh.

### ALPN и iroh endpoint

`DaemonHandle::start()` создаёт iroh endpoint с `RelayMode::Disabled`.
На localhost два endpoint'а найдут друг друга по локальному UDP.
`StatusPayload.own_node_id` = `EndpointAddr::to_string()`.
`ConnectAddr` использует `EndpointAddr::from_str()` для парсинга.

### Таймауты

| Шаг | Таймаут |
|-----|---------|
| Ожидание socket'а | 2 секунды (20 × 100 мс) |
| Ожидание shards_placed | 30 секунд |
| Ожидание файла при restore | 30 секунд |
| Весь тест 3 | 120 секунд |

### Эскроу при restore

РЕШЕНО: тестовые файлы суммарно ~ 80 КБ, попадают в FreeTier (< 1 ГБ).
`EscrowChecker::check_restore()` возвращает `Allow` без проверки `weeks_in_network`.

### System state / DB

РЕШЕНО: вариант (c) — DB копируется из dir_a в dir_c. Node C знает shard map.
Полный DR без DB (system state recovery) = Phase 4.

---

## Checklist для implementer'а

### Шаг 1: Доработки существующих модулей

- [ ] `StatusPayload` + `StatusReply` содержат `own_node_id: String`
- [ ] Processor передаёт EndpointAddr.to_string() в StatusReply
- [ ] `CliRequest::ConnectPeer { node_addr }` добавлен
- [ ] `CliCmd::ConnectPeer { node_addr }` добавлен
- [ ] `cli_server::dispatch` обрабатывает ConnectPeer
- [ ] Processor обрабатывает ConnectPeer → NetCommand::ConnectAddr
- [ ] `DirectBody::ShardData(ShardDataMsg)` добавлен в messages.rs
- [ ] `ConnectAddr` реализован в network (endpoint.connect + handshake)
- [ ] Holder: RestoreRequest → read shard → send ShardData response
- [ ] Owner: `handle_cli_restore` — DB lookup → download k shards → RS decode → decrypt → write

### Шаг 2: GATE тесты

- [ ] `crates/syncback/tests/phase3_gate.rs` с 3 тестами
- [ ] Все 3 теста проходят с `--test-threads=1`
- [ ] Существующие 340 тестов не сломаны

### Visibility

- [ ] `DaemonHandle`, `Config` и sub-structs — pub для tests/
- [ ] `daemon::cli_server::{CliRequest, CliResponse, StatusPayload}` — pub
- [ ] `cli::init::init_with_mnemonic` — pub

---

## Команды запуска

```bash
# Все phase3 тесты (медленные, однопоточно):
cargo test -p syncback phase3 -- --test-threads=1 --nocapture

# Только быстрый тест 1:
cargo test -p syncback daemon_starts_and_responds_to_status -- --nocapture

# Docker вариант (из корня проекта):
bash tests/docker/run_tests.sh
```

---

## Зависимости от других модулей

| Модуль | Что нужно |
|--------|-----------|
| `daemon/mod.rs` | `DaemonHandle::start`, `Config`, `StatusReply` с `own_node_id` |
| `daemon/cli_server/mod.rs` | `CliRequest`, `CliResponse`, `StatusPayload` с `own_node_id` |
| `daemon/processor/mod.rs` | обработка `CliCmd::ConnectPeer` |
| `cli/init.rs` | `init_with_mnemonic` — уже реализована |
| `daemon/network/mod.rs` | `NetworkHandle::endpoint_addr` для получения NodeId |

Все зависимые модули уже реализованы. Gate тесты — последний шаг.
