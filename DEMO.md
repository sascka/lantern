<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Демонстрация Lantern v0.1

Эта инструкция проводит одно сообщение по маршруту Alice -> Relay -> Bob.
Alice и Bob не соединяются друг с другом. После первой встречи соединение Alice
закрывается, и только потом Relay встречает Bob.

Демонстрация предназначена для проверки experimental preview на Arch Linux. Не
используйте настоящие пароли и личные сообщения. Независимого аудита у Lantern
пока не было.

## 1. Сборка

```bash
sudo pacman -S --needed rustup base-devel clang git python

cd "/home/qual/Desktop/prog/Lantern proj"
rustup toolchain install 1.97.1 --profile minimal \
  --component clippy,rustfmt
cargo build -p lantern-cli --release --locked
```

Во всех следующих командах оставайтесь в корне репозитория.

## 2. Чистый каталог

```bash
rm -rf .demo
umask 077
mkdir -m 700 .demo .demo/exchange

printf '%s' 'alice demo passphrase 2026' > .demo/alice.pass
printf '%s' 'bob demo passphrase 2026' > .demo/bob.pass
printf '%s' 'message through an offline relay' > .demo/message.txt
chmod 600 .demo/alice.pass .demo/bob.pass .demo/message.txt
```

Это только демонстрационные значения. Для личного запуска парольную фразу
лучше читать через `read -rs` и не сохранять команды с ней в истории shell.

Создайте два секретных профиля и три открытых узла:

```bash
./target/release/lantern-cli profile-init \
  .demo/alice-profile .demo/alice.pass
./target/release/lantern-cli profile-init \
  .demo/bob-profile .demo/bob.pass

./target/release/lantern-cli node-init .demo/alice-node
./target/release/lantern-cli node-init .demo/relay-node
./target/release/lantern-cli node-init .demo/bob-node
```

## 3. Добавление контакта

Откройте два терминала. Команды должны работать одновременно, потому что
временное состояние SAS не сохраняется.

Терминал Alice:

```bash
cd "/home/qual/Desktop/prog/Lantern proj"
./target/release/lantern-cli contact-invite \
  .demo/alice-profile .demo/alice.pass Bob \
  .demo/exchange/invitation.qr \
  .demo/exchange/response.qr \
  .demo/exchange/bob-confirmation.cbor \
  .demo/exchange/alice-confirmation.cbor
```

Терминал Bob:

```bash
cd "/home/qual/Desktop/prog/Lantern proj"
./target/release/lantern-cli contact-respond \
  .demo/bob-profile .demo/bob.pass Alice \
  .demo/exchange/invitation.qr \
  .demo/exchange/response.qr \
  .demo/exchange/bob-confirmation.cbor \
  .demo/exchange/alice-confirmation.cbor
```

Обе команды покажут строку `SAS:` с тремя числами. Сверьте её целиком по
голосу или лично. Если числа совпали, введите `MATCH` в обоих терминалах. При
любом различии остановите обе команды, удалите `.demo/exchange` и начните этот
раздел заново.

Если только одна команда успела показать `Contact is active.`, не повторяйте
обмен поверх тех же профилей. В v0.1 нет удаления одностороннего контакта.
Удалите весь тестовый каталог `.demo`, вернитесь к разделу 2 и создайте оба
профиля заново.

Проверьте список контактов:

```bash
./target/release/lantern-cli contacts \
  .demo/alice-profile .demo/alice.pass
./target/release/lantern-cli contacts \
  .demo/bob-profile .demo/bob.pass
```

Alice должна видеть `Bob`, Bob - `Alice`. Рядом будет стабильный отпечаток
ключа, но не внутренний идентификатор контакта.

## 4. Создание сообщения без Bob

```bash
./target/release/lantern-cli send \
  .demo/alice-profile .demo/alice.pass .demo/alice-node \
  Bob .demo/message.txt 3600 2
```

Bob в этот момент не запущен и не имеет соединения с Alice. Команда сохраняет
зашифрованный Envelope в очередь Alice.

## 5. Встреча Alice с Relay

В новом терминале запустите Relay:

```bash
cd "/home/qual/Desktop/prog/Lantern proj"
./target/release/lantern-cli listen \
  .demo/relay-node 127.0.0.1:38101
```

В основном терминале подключите Alice:

```bash
./target/release/lantern-cli connect \
  .demo/alice-node 127.0.0.1:38101
```

Дождитесь завершения обеих команд. Теперь Alice отключена, а Relay хранит
только зашифрованный контейнер.

## 6. Встреча Relay с Bob

Запустите Bob в новом терминале:

```bash
cd "/home/qual/Desktop/prog/Lantern proj"
./target/release/lantern-cli listen \
  .demo/bob-node 127.0.0.1:38102
```

Подключите Relay:

```bash
./target/release/lantern-cli connect \
  .demo/relay-node 127.0.0.1:38102
```

Эта встреча начинается после полного завершения связи Alice с Relay. Прямого
сокета Alice -> Bob в инструкции нет.

## 7. Открытие у Bob

```bash
./target/release/lantern-cli receive \
  .demo/bob-profile .demo/bob.pass .demo/bob-node
```

Ожидаемый результат:

```text
MESSAGE: message through an offline relay
Receive complete: opened 1, recovered 0, rejected 0.
```

Повторите ту же команду. Второй запуск должен показать `opened 0` и не должен
печатать сообщение второй раз.

История Bob доступна отдельно:

```bash
./target/release/lantern-cli inbox \
  .demo/bob-profile .demo/bob.pass
```

`receive` и `inbox` намеренно выводят текст. Не отправляйте их вывод в общий
лог.

## 8. Relay и диагностика

```bash
./target/release/lantern-cli diagnostics .demo/relay-node
test ! -e .demo/relay-node/secrets.kdf
test ! -e .demo/relay-node/secrets.sqlite3
```

Обе команды `test` должны завершиться без вывода и с кодом 0. Это подтверждает,
что демонстрационный Relay не получил секретный профиль. Оно не доказывает,
что зашифрованный контейнер скрывает все метаданные или что реализация
безопасна.

## Запуск на трёх компьютерах

Для трёх физических Linux-компьютеров используйте разные каталоги и замените
`127.0.0.1` локальными адресами Relay и Bob. Файлы контактного обмена нужно
передавать по доверенному каналу, сохраняя права `0600`. Каждый процесс ожидает
следующий файл не больше двух минут.

В репозитории автоматически проверяется тот же порядок на loopback в трёх
отдельных CLI-процессах. Физические сетевые карты, файрволы и потеря питания в
эту проверку не входят.
