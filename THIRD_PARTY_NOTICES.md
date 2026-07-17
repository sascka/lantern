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
| `argon2` | 0.5.3 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2021-2024 The RustCrypto Project Developers |
| `base64ct` | 1.8.3 | `MIT` из `Apache-2.0 OR MIT` | Copyright (c) 2014 Steve "Sc00bz" Thomas; Copyright (c) 2021-2025 The RustCrypto Project Developers |
| `bitflags` | 2.13.1 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 The Rust Project Developers |
| `blake2` | 0.10.6 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2015-2016 The blake2-rfc Developers, Cesar Barros; Copyright (c) 2017 Artyom Pavlov |
| `block-buffer` | 0.10.4 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2018-2019 The RustCrypto Project Developers |
| `cfg-if` | 1.0.4 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 Alex Crichton |
| `cpufeatures` | 0.2.17 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2020-2025 The RustCrypto Project Developers |
| `crypto-common` | 0.1.7 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2021 RustCrypto Developers |
| `digest` | 0.10.7 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2017 Artyom Pavlov |
| `fallible-iterator` | 0.3.0 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2015 The rust-openssl-verify Developers |
| `fallible-streaming-iterator` | 0.1.9 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2016 The fallible-streaming-iterator Developers |
| `generic-array` | 0.14.7 | `MIT` | Copyright (c) 2015 Bartłomiej Kamiński |
| `getrandom` | 0.4.3 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2018-2026 The rust-random Project Developers; Copyright (c) 2014 The Rust Project Developers |
| `libc` | 0.2.186 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) The Rust Project Developers |
| `libsqlite3-sys` | 0.38.1 | `MIT` | Copyright (c) 2014 The rusqlite developers |
| `smallvec` | 1.15.2 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2018 The Servo Project Developers |
| `subtle` | 2.6.1 | `BSD-3-Clause` | Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence; Copyright (c) 2016-2024 Isis Agora Lovecruft |
| `typenum` | 1.20.1 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 Paho Lurie-Gregg |
| `zeroize` | 1.9.0 | `MIT` из `Apache-2.0 OR MIT` | Copyright (c) 2018-2026 The RustCrypto Project Developers |

### Криптографическое дерево

После закрытия криптографического рубежа runtime-дерево дополнено следующими
пакетами. Точные checksums и зависимости находятся в `Cargo.lock`.

| Пакет | Версия | Выбранная лицензия |
| --- | --- | --- |
| `vodozemac` | 0.10.0 | `Apache-2.0` |
| `matrix-pickle`, `matrix-pickle-derive` | 0.2.3 | `Apache-2.0` |
| `prost`, `prost-derive` | 0.14.4 | `Apache-2.0` |
| `base64` | 0.22.1 | `MIT` из `MIT OR Apache-2.0` |
| `aes` | 0.8.4 | `MIT` из `MIT OR Apache-2.0` |
| `aead` | 0.5.2 | `MIT` из `MIT OR Apache-2.0` |
| `cbc` | 0.1.2 | `MIT` из `MIT OR Apache-2.0` |
| `chacha20` | 0.9.1 | `MIT` из `Apache-2.0 OR MIT` |
| `chacha20poly1305` | 0.10.1 | `MIT` из `Apache-2.0 OR MIT` |
| `cipher` | 0.4.4 | `MIT` из `MIT OR Apache-2.0` |
| `poly1305` | 0.8.0 | `MIT` из `Apache-2.0 OR MIT` |
| `universal-hash` | 0.5.1 | `MIT` из `MIT OR Apache-2.0` |
| `hkdf` | 0.12.4 | `MIT` из `MIT OR Apache-2.0` |
| `hmac` | 0.12.1 | `MIT` из `MIT OR Apache-2.0` |
| `sha2` | 0.10.9 | `MIT` из `MIT OR Apache-2.0` |
| `curve25519-dalek` | 4.1.3 | `BSD-3-Clause` |
| `curve25519-dalek-derive` | 0.1.1 | `MIT` из `MIT OR Apache-2.0` |
| `ed25519-dalek` | 2.2.0 | `BSD-3-Clause` |
| `ed25519` | 2.2.3 | `MIT` из `Apache-2.0 OR MIT` |
| `x25519-dalek` | 2.0.1 | `BSD-3-Clause` |
| `signature` | 2.2.0 | `MIT` из `Apache-2.0 OR MIT` |
| `rand`, `rand_chacha` | 0.8.7, 0.3.1 | `MIT` из `MIT OR Apache-2.0` |
| `rand_core` | 0.6.4 | `MIT` из `MIT OR Apache-2.0` |
| `getrandom` | 0.2.17 | `MIT` из `MIT OR Apache-2.0` |
| `arrayvec` | 0.7.8 | `MIT` из `MIT OR Apache-2.0` |
| `bytes` | 1.12.1 | `MIT` |
| `serde`, `serde_bytes`, `serde_json` | 1.0.228, 0.11.19, 1.0.150 | `MIT` из dual license |
| `thiserror`, `thiserror-impl` | 2.0.18 | `MIT` из `MIT OR Apache-2.0` |

Полный Apache-2.0 сохранён в
[`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt). BSD-3-Clause имеет
одинаковые условия, но copyright-уведомления сохраняются из соответствующих
пакетов при распространении исходников.

## Зависимости сборки

| Пакет | Версия | Выбранная лицензия | Copyright из пакета |
| --- | --- | --- | --- |
| `cc` | 1.2.67 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 Alex Crichton |
| `find-msvc-tools` | 0.1.9 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 Alex Crichton |
| `shlex` | 2.0.1 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2015 Nicholas Allegra (comex). |
| `pkg-config` | 0.3.33 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 Alex Crichton |
| `vcpkg` | 0.2.15 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2017 Jim McGrath |
| `version_check` | 0.9.5 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2017-2018 Sergio Benitez |

## Dev-зависимости property-тестов

Эти пакеты нужны только для сборки и запуска тестов. В обычную
сборку библиотек Lantern они не входят.

| Пакет | Версия | Выбранная лицензия | Copyright из пакета |
| --- | --- | --- | --- |
| `proptest` | 1.11.0 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2016 FullContact, Inc |
| `autocfg` | 1.5.1 | `MIT` из `Apache-2.0 OR MIT` | Copyright (c) 2018 Josh Stone |
| `getrandom` | 0.3.4 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2018-2025 The rust-random Project Developers; Copyright (c) 2014 The Rust Project Developers |
| `num-traits` | 0.2.19 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 The Rust Project Developers |
| `ppv-lite86` | 0.2.21 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2019 The CryptoCorrosion Contributors |
| `rand` | 0.9.5 | `MIT` из `MIT OR Apache-2.0` | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| `rand_chacha` | 0.9.0 | `MIT` из `MIT OR Apache-2.0` | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| `rand_core` | 0.9.5 | `MIT` из `MIT OR Apache-2.0` | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| `rand_xorshift` | 0.4.0 | `MIT` из `MIT OR Apache-2.0` | Copyright 2018 Developers of the Rand project; Copyright (c) 2014 The Rust Project Developers |
| `regex-syntax` | 0.8.11 | `MIT` из `MIT OR Apache-2.0` | Copyright (c) 2014 The Rust Project Developers |
| `unarray` | 0.1.4 | `MIT` из `MIT OR Apache-2.0` | в `LICENSE-MIT` оставлен незаполненный шаблон |
| `zerocopy` | 0.8.54 | `MIT` из `BSD-2-Clause OR Apache-2.0 OR MIT` | Copyright 2023 The Fuchsia Authors |

Ещё девять пакетов записаны в `Cargo.lock` для других целевых платформ
и proc-macro-ветвей. В проверенное Linux-дерево `proptest` они не входят.

| Пакет | Версия | Выбранная лицензия | Copyright из пакета |
| --- | --- | --- | --- |
| `proc-macro2` | 1.0.106 | `MIT` из `MIT OR Apache-2.0` | отдельная строка не указана |
| `quote` | 1.0.46 | `MIT` из `MIT OR Apache-2.0` | отдельная строка не указана |
| `r-efi` | 5.3.0 | `MIT` из `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | Copyright (C) 2017-2023 Red Hat, Inc.; Copyright (C) 2019-2023 Microsoft Corporation; Copyright (C) 2022-2023 David Rheinsberg |
| `r-efi` | 6.0.0 | `MIT` из `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | Copyright (C) 2017-2023 Red Hat, Inc.; Copyright (C) 2019-2023 Microsoft Corporation; Copyright (C) 2022-2023 David Rheinsberg |
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
Текст BSD-3-Clause для `subtle` сохранён в
[`LICENSES/BSD-3-Clause-subtle.txt`](LICENSES/BSD-3-Clause-subtle.txt).

Bundled SQLCipher 4.17.0 на базе SQLite 3.53.3 включён через точный Git rev
`libsqlite3-sys` 0.38.1. Код SQLCipher распространяется по BSD-3-Clause
Zetetic, полный текст и copyright сохранены в
[`LICENSES/BSD-3-Clause-SQLCipher.txt`](LICENSES/BSD-3-Clause-SQLCipher.txt).
Основная часть SQLite передана в public domain. Официальное описание статуса:
<https://www.sqlite.org/copyright.html>.

Версии в этом документе должны совпадать с `Cargo.lock`. При обновлении любого
пакета нужно повторно проверить его metadata, полный текст лицензии,
уведомления и дерево зависимостей.
