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

## Dev-зависимости property-тестов

Эти пакеты нужны только для сборки и запуска тестов. В обычную
сборку библиотек Lantern они не входят.

| Пакет | Версия | Выбранная лицензия | Copyright из пакета |
| --- | --- | --- | --- |
| `proptest` | 1.11.0 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2016 FullContact, Inc |
| `autocfg` | 1.5.1 | `MIT` из `Apache-2.0 OR MIT` | Copyright (c) 2018 Josh Stone |
| `cfg-if` | 1.0.4 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 Alex Crichton |
| `getrandom` | 0.3.4 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2018-2025 The rust-random Project Developers; Copyright (c) 2014 The Rust Project Developers |
| `libc` | 0.2.186 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) The Rust Project Developers |
| `num-traits` | 0.2.19 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 The Rust Project Developers |
| `ppv-lite86` | 0.2.21 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2019 The CryptoCorrosion Contributors |
| `rand` | 0.9.5 | `MIT` из `MIT OR Apache-2.0` | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| `rand_chacha` | 0.9.0 | `MIT` из `MIT OR Apache-2.0` | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| `rand_core` | 0.9.5 | `MIT` из `MIT OR Apache-2.0` | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| `rand_xorshift` | 0.4.0 | `MIT` из `MIT OR Apache-2.0` | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| `regex-syntax` | 0.8.11 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 The Rust Project Developers |
| `unarray` | 0.1.4 | `MIT` из `MIT OR Apache-2.0` | в `LICENSE-MIT` оставлен незаполненный шаблон |
| `zerocopy` | 0.8.54 | `MIT` из `BSD-2-Clause OR Apache-2.0 OR MIT` | Copyright 2023 The Fuchsia Authors |

Ещё восемь пакетов записаны в `Cargo.lock` для других целевых платформ
и proc-macro-ветвей. В проверенное Linux-дерево `proptest` они не входят.

| Пакет | Версия | Выбранная лицензия | Copyright из пакета |
| --- | --- | --- | --- |
| `proc-macro2` | 1.0.106 | `MIT` из `MIT OR Apache-2.0` | отдельная строка не указана |
| `quote` | 1.0.46 | `MIT` из `MIT OR Apache-2.0` | отдельная строка не указана |
| `r-efi` | 5.3.0 | `MIT` из `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | Copyright (C) 2017-2023 Red Hat, Inc.; Copyright (C) 2019-2023 Microsoft Corporation; Copyright (C) 2022-2023 David Rheinsberg |
| `syn` | 2.0.119 | `MIT` из `MIT OR Apache-2.0` | отдельная строка не указана |
| `unicode-ident` | 1.0.24 | `MIT AND Unicode-3.0` | Copyright © 1991-2023 Unicode, Inc. |
| `wasip2` | 1.0.4+wasi-0.2.12 | `MIT` из `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | отдельная строка не указана |
| `wit-bindgen` | 0.57.1 | `MIT` из `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | отдельная строка не указана |
| `zerocopy-derive` | 0.8.54 | `MIT` из `BSD-2-Clause OR Apache-2.0 OR MIT` | Copyright 2023 The Fuchsia Authors |

Полный текст Blue Oak находится в
[`LICENSES/BlueOak-1.0.0.txt`](LICENSES/BlueOak-1.0.0.txt). Агрегированный текст
MIT со всеми нужными copyright-строками находится в
[`LICENSES/MIT-third-party.txt`](LICENSES/MIT-third-party.txt).
Дополнительный текст Unicode-3.0 из пакета `unicode-ident` сохранён
в [`LICENSES/Unicode-3.0.txt`](LICENSES/Unicode-3.0.txt).

Bundled SQLite 3.53.2 включён в `libsqlite3-sys` 0.38.1. Авторы SQLite передали
его в public domain. Официальное описание статуса:
<https://www.sqlite.org/copyright.html>.

Версии в этом документе должны совпадать с `Cargo.lock`. При обновлении любого
пакета нужно повторно проверить его metadata, полный текст лицензии,
уведомления и дерево зависимостей.
