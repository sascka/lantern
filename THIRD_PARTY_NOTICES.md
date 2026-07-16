<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Уведомления о сторонних компонентах

Статус: зависимости workspace на 17 июля 2026 года.

Этот файл не меняет лицензии сторонних компонентов. Он фиксирует версии,
выбранную ветвь dual license и уведомления, которые должны сопровождать
распространение Lantern.

## Rust-зависимости runtime

| Пакет | Версия | Выбранная лицензия | Copyright из пакета |
| --- | --- | --- | --- |
| `minicbor` | 2.2.2 | `BlueOak-1.0.0` | указано в полном тексте пакета |
| `rusqlite` | 0.40.1 | `MIT` | Copyright (c) 2014 The rusqlite developers |
| `bitflags` | 2.13.1 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 The Rust Project Developers |
| `fallible-iterator` | 0.3.0 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2015 The rust-openssl-verify Developers |
| `fallible-streaming-iterator` | 0.1.9 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2016 The fallible-streaming-iterator Developers |
| `libsqlite3-sys` | 0.38.1 | `MIT` | Copyright (c) 2014 The rusqlite developers |
| `smallvec` | 1.15.2 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2018 The Servo Project Developers |

## Зависимости сборки bundled SQLite

| Пакет | Версия | Выбранная лицензия | Copyright из пакета |
| --- | --- | --- | --- |
| `cc` | 1.2.67 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 Alex Crichton |
| `find-msvc-tools` | 0.1.9 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 Alex Crichton |
| `shlex` | 2.0.1 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2015 Nicholas Allegra (comex). |
| `pkg-config` | 0.3.33 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 Alex Crichton |
| `vcpkg` | 0.2.15 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2017 Jim McGrath |

Полный текст Blue Oak находится в
[`LICENSES/BlueOak-1.0.0.txt`](LICENSES/BlueOak-1.0.0.txt). Агрегированный текст
MIT со всеми нужными copyright-строками находится в
[`LICENSES/MIT-third-party.txt`](LICENSES/MIT-third-party.txt).

Bundled SQLite 3.53.2 включён в `libsqlite3-sys` 0.38.1. Авторы SQLite передали
его в public domain. Официальное описание статуса:
<https://www.sqlite.org/copyright.html>.

Версии в этом документе должны совпадать с `Cargo.lock`. При обновлении любого
пакета нужно повторно проверить его metadata, полный текст лицензии,
уведомления и дерево зависимостей.
