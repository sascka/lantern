<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Результат проверки SQLCipher 4.17.0

Дата проверки: 17 июля 2026 года.

## Что собиралось

- `rusqlite 0.40.1`;
- `libsqlite3-sys 0.38.1` из официального commit
  `5ae7fdf83085c595fd54f977b3a56ccacabaf16b`;
- bundled SQLCipher `4.17.0 community`;
- системный OpenSSL на Arch Linux;
- Rust 1.97.1.

Git rev зафиксирован и в `Cargo.toml`, и в отдельном `Cargo.lock` эксперимента.
`build.rs` не загружает исходники по сети во время сборки.

## Фактический результат

Команды:

```bash
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

Завершились успешно. Прошли четыре теста:

- библиотека сообщает точную версию `4.17.0 community`;
- 32-байтный raw key создаёт базу без открытого SQLite header и контрольного
  plaintext;
- неверный ключ не читает базу и не может добавить таблицу;
- тот же native build продолжает открывать обычную plaintext SQLite-базу для
  транспортной очереди.

Тест с неверным ключом после ошибки повторно открывает базу правильным ключом и
проверяет, что таблица злоумышленника не появилась.

## Что этот результат не доказывает

Проверка не является аудитом SQLCipher, OpenSSL, `rusqlite` или Lantern. Она не
исследует утечки по времени, swap, дампы процесса и все варианты аварийного
завершения. Любая смена SQLCipher, OpenSSL, Git rev или feature требует нового
прогона.
