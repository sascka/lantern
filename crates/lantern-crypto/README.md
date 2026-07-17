<!-- SPDX-License-Identifier: MPL-2.0 -->

# lantern-crypto

`lantern-crypto` хранит транспортно-независимую границу E2EE Lantern.

Crate отвечает за строгие форматы контактных bundle, внутреннего сообщения и
Olm-оболочки, а также за работу с `vodozemac 0.10.0`. Он не открывает сокеты и
не знает, каким способом Envelope попал на устройство.

Внутри есть:

- invite длиной 292 байта и response длиной 272 байта;
- строгий QR `lantern-contact-v1:` с Base64URL;
- SAS через готовый API `vodozemac`;
- два подтверждения контакта и одна двусторонняя Olm-сессия;
- три поля открытой Olm-оболочки и семь внутренних типов;
- кандидатный ratchet при входящем сообщении;
- транзакционный исходящий и входящий chat-путь через
  `lantern-secret-storage`.

`lantern-crypto` не зависит от `lantern-transport`. Сеть и Relay видят только
готовый Envelope.

## Проверка

```bash
cd "/home/qual/Desktop/prog/Lantern proj"
export PATH="$HOME/.cargo/bin:$PATH"

cargo fmt --all --check
cargo clippy -p lantern-crypto --all-targets --locked -- -D warnings
cargo test -p lantern-crypto --all-targets --locked
```

Тесты содержат точные vectors всех внутренних типов и обеих Olm-оболочек,
меняют внешние поля при неизменном ciphertext, проверяют откат кандидата,
replay, 32 сообщения в обратном порядке и произвольный ограниченный ввод.

Это реализация для `Lantern v0.1 experimental preview`. Она не проходила
coverage-guided fuzzing и независимый аудит. Olm v1 использует известную
64-битную границу MAC. Проект не должен называться безопасным мессенджером.
