<!-- SPDX-License-Identifier: MPL-2.0 -->

# Lantern Secret Storage

Статус: рабочее секретное хранилище для `Lantern v0.1 experimental preview`.

`lantern-secret-storage` отвечает за:

- строгий `secrets.kdf` и Argon2id 1.3;
- профиль с каталогом `0700` и файлами `0600`;
- SQLCipher 4.17.0 с raw key;
- зашифрованные Account и Session pickle;
- контакты, локальную историю и постоянный limiter;
- attempt marker до decrypt;
- pending outbox с готовым неизменяемым Envelope.

Транспорт не получает соединение с этой базой. Открытая очередь остаётся в
`lantern-storage` и хранит только готовые Envelope.

## Пароль и KDF

`Passphrase` принимает от 16 до 128 Unicode-символов и не больше 1024 байт
UTF-8. Строка не обрезается и не нормализуется. Тип обнуляет свои bytes при
удалении. `DatabaseKey` также обнуляется и не открывает ключ через публичный
API.

Заголовок KDF является строгим каноническим CBOR. Параметры фиксированы:

- Argon2id 1.3;
- случайная соль 16 байт;
- 65536 KiB памяти;
- 3 прохода;
- 4 lanes;
- результат 32 байта.

После KDF все 64 MiB рабочих блоков обнуляются. Это уменьшает число остаточных
копий, но не защищает от swap, debugger, core dump или вредоносного процесса.

## SQLCipher

Опубликованный `libsqlite3-sys 0.38.1` ещё содержал SQLCipher 4.14.0. Workspace
временно фиксирует точный commit
`5ae7fdf83085c595fd54f977b3a56ccacabaf16b` официального `rusqlite`, в котором
bundled SQLCipher обновлён до 4.17.0. Отдельный стенд находится в
[`experiments/sqlcipher-compat`](../../experiments/sqlcipher-compat/README.md).

При открытии проверяются версия SQLCipher, application ID, версия схемы,
размеры, связи и квоты. Используются rollback journal, memory security,
`temp_store = MEMORY`, `mmap_size = 0`, foreign keys и secure delete.

Неверный пароль, повреждённая первая страница и неверный raw key возвращают
одну закрытую категорию. Ошибки не содержат путь, SQL, ключ или данные базы.

## Транзакции

Исходящая операция сохраняет новый Session и готовый Envelope в pending outbox
одной транзакцией. После перезапуска наружу копируются те же bytes, без второго
encrypt.

`lantern-bridge` читает outbox по одной записи в исходном порядке. Запись
удаляется только после сохранения точного Envelope в открытой очереди. Для
входящего пути хранилище находит единственный активный контакт по одному из трёх
допустимых входных hint и проверяет историю при восстановлении после сбоя.

При завершении добавления контакта Alice изменённый Account, активный контакт и
Session записываются одной транзакцией. Bob использует более узкий вариант с
контактом и Session. Активный контакт можно прочитать только через уже
разблокированный `SecretStore`; его `Debug` не раскрывает имя, ключи или hints.

Входящая операция сначала сохраняет уменьшенные limiter bucket и attempt
marker. Только после commit вызывается decrypt на кандидатном Session. Полный
успех одной следующей транзакцией сохраняет ratchet, историю, возврат одного
token и успешный marker. До этого plaintext не выдаётся вызывающему коду.

Между перезапусками token не восстанавливаются за offline-время. Runtime anchor
начинается заново от монотонного времени процесса.

## Проверка на Arch Linux

```bash
sudo pacman -S --needed rustup base-devel openssl pkgconf

cd "/home/qual/Desktop/prog/Lantern proj"
export PATH="$HOME/.cargo/bin:$PATH"

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked

cd experiments/sqlcipher-compat
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

## Ограничения

- Терминальный ввод пароля без отображения появится вместе с CLI.
- Слабую парольную фразу можно подбирать по украденной базе офлайн.
- SQLCipher и системный OpenSSL добавляют native-код.
- Длительные испытания аварийного завершения и независимый аудит не проведены.
- Хранилище не защищает секреты после компрометации разблокированного процесса.
- Эта реализация не позволяет называть Lantern безопасным.
