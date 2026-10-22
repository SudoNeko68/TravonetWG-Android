# TravonetWG для Android

Android-адаптация [wireguard-go](https://git.zx2c4.com/wireguard-go/) в виде нативной
разделяемой библиотеки `.so`. Предназначена для интеграции в Android-приложения через
JNI и не требует root, `CAP_NET_RAW` или `CAP_NET_ADMIN`.

Библиотека работает с любыми стандартными серверами WireGuard и добавляет
пользовательскую (userspace) десинхронизацию DPI/ТСПУ, безопасную для нерутованного
Android.

---

## Что внутри

- **VpnService backend** — TUN-дескриптор передаётся из Java в Go через
  `CreateUnmonitoredTUNFromFD(fd)`.
- **Защита сокетов** — `VpnService.protect(fd)` вызывается до `bind()` и до первого
  Handshake, поэтому трафик не уходит в петлю через `tun0`.
- **Userspace DPI evasion** — только обычные UDP-сокеты: подмена TTL через
  `sendmsg()` + `cmsg IP_TTL`, fake/junk/mimic-пакеты, IPv4 options, `jumbo_fake`
  с фрагментацией силами ядра.
- **Auto-TTL без root** — расстояние до сервера измеряется через
  `IP_RECVERR` / `MSG_ERRQUEUE`; внешние `traceroute`/`tracepath` не используются.
- **Port hopping** — при динамическом локальном порте (`listen_port = 0`) сокет
  переоткрывается с новым эфемерным портом при неудачном рукопожатии.
- **SOCKS5 без разрешений** — встроенный прокси на базе gVisor netstack.
- **Совместимость JNI** — символы для `com.wireguard.android.backend.GoBackend`,
  `org.amnezia.vpn.protocol.amneziawg.GoBackend` и
  `org.travonet.backend.GoBackend`.

---

## Чего здесь нет

Адаптация сознательно не содержит функциональности, невозможной на нерутованном
Android:

- raw-сокетов (`AF_INET/SOCK_RAW`, `IP_HDRINCL`, `IP_NODEFRAG`);
- ручной L3-фрагментации пакета рукопожатия и действий `frag()` / `fake_frag()`;
- подделки UDP-контрольной суммы (`badsum`);
- внешнего `traceroute` и запуска сторонних бинарников;
- десктопных entrypoint'ов, Windows/BSD/Darwin-реализаций и UAPI-сокета,
  который на обычном Android всё равно недоступен приложению.

Старые имена стратегий (`default`, `5packet`, `ipfrag2`, `split2`, `fake`)
автоматически отображаются на userspace-стратегию. Явно заданные `frag()` /
`fake_frag()` отклоняются, и движок использует безопасный default-userspace.

---

## Быстрый старт

### 1. Сборка `.so`

Требования:

- Go 1.22+;
- Android NDK r26+ (проверено на r27c);
- Linux/macOS хост с `clang` из NDK.

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
./build-android.sh
```

Результат:

```text
build/android/jniLibs/<ABI>/libtravonet-wg.so
build/android/jniLibs/<ABI>/libwg-go.so
```

ABI: `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`.
`libwg-go.so` — побайтовая копия для drop-in совместимости с клиентами WireGuard
Android.

Можно указать свой каталог вывода:

```bash
OUT_DIR=/path/to/jniLibs ./build-android.sh
```

### 2. Запуск VpnService-туннеля

```java
// Рекомендуемый путь: передать VpnService в native-слой до запуска.
int handle = GoBackend.wgTurnOnProtected(
        "wg0",
        tunFd,
        configText,   // WireGuard .conf или UAPI
        vpnService
);
if (handle < 0) {
    throw new IllegalStateException("wgTurnOnProtected failed");
}
```

Legacy-клиенты, которые умеют только `protect(fd)` после создания туннеля:

```java
int handle = GoBackend.wgTurnOn("wg0", tunFd, configText);
int fd = GoBackend.wgGetSocketV4(handle);
vpnService.protect(fd);
GoBackend.wgNotifySocketProtected(handle);
```

Остановка:

```java
GoBackend.wgTurnOff(handle);
```

### 3. SOCKS5 без VpnService

```java
int socks = GoBackend.wgStartSocks5("127.0.0.1:1080", configText);
// ...
GoBackend.wgStopSocks5(socks);
```

Проверка:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

---

## Конфигурация

Стратегия и параметры evasion задаются в секции `[Interface]` обычного `.conf`:

```ini
[Interface]
PrivateKey = ...
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280

# userspace-стратегия; можно не указывать
Strategy = default-userspace
FakeTTL = auto
NormalTTL = 64
PreJunk = 64

[Peer]
PublicKey = ...
Endpoint = 162.159.192.1:2408
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Также поддерживается UAPI-формат. AmneziaWG-ключи (`jc`, `jmax`, `s1`–`s4`,
`h1`–`h4`, `i1`–`i5`) отбрасываются, а `jmin` при отсутствии `PreJunk`
используется как размер pre-junk.

### Параметры

| Параметр | Описание |
| :--- | :--- |
| `Strategy` | userspace-DSL или алиас (`default`, `default-userspace`, `fake`) |
| `FakeTTL` | TTL фейковых пакетов; `auto` включает kernel-зондирование |
| `NormalTTL` | TTL легитимного рукопожатия и транспортных пакетов |
| `PreJunk` / `jmin` | размер случайного UDP-пакета перед рукопожатием |
| `MTU` | MTU TUN-интерфейса (по умолчанию 1280, применяется через `Device.SetMTU`) |
| `PersistentKeepalive` | keepalive; для endpoint'ов на порту 500 автоматически не более 5 с |

---

## DSL: userspace-действия

Шаги разделяются `->`, `;` или переводами строк.

| Действие | Назначение | Пример |
| :--- | :--- | :--- |
| `junk(size, ttl=)` | случайный UDP-пакет | `junk(64)` |
| `fake_udp(size, ttl=, ipopt=, corrupt=)` | фейковый WireGuard-handshake | `fake_udp(148, ttl=5, ipopt=ts, corrupt=true)` |
| `mimic(quic\|stun\|dns)` | маскировка под чужой протокол | `mimic(quic)` |
| `jumbo_fake(size=1600)` | крупный UDP-пакет, фрагментируемый ядром | `jumbo_fake(1600)` |
| `ipopt_shift(size, mode=nop\|ts\|rr)` | IPv4 options для легитимного handshake | `ipopt_shift(8, mode=ts)` |
| `sleep(10ms)` | пауза между шагами | `sleep(5ms)` |

Встроенная стратегия:

```text
mimic(quic) -> mimic(stun) -> jumbo_fake(1600) -> fake_udp(148, ipopt=ts) -> sleep(2ms)
```

Примеры:

```text
junk(64) -> fake_udp(148, ttl=5)
mimic(dns) -> junk(96) -> fake_udp(148, ttl=4) -> sleep(3ms)
```

---

## Ограничения

- Десинхронизация DPI применяется к IPv4-endpoint'ам; IPv6 идёт стандартным путём.
- `jumbo_fake` использует фрагментацию IPv4 силами ядра, а не raw-сокеты.
- На некоторых прошивках SELinux запрещает `TUNGETIFF`/`SIOCGIFMTU`; библиотека
  использует безопасные значения по умолчанию (имя `tun0`, MTU 1280).
- Одна универсальная стратегия невозможна: параметры зависят от оператора и
  региона. Стратегии стоит подбирать под конкретную сеть.

---

## Проверка сборки

```bash
go test ./conf ./conn ./proxy
GOOS=android GOARCH=arm64 CGO_ENABLED=1 \
  CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang \
  go vet ./android
```

Проверить JNI-символы:

```bash
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm -D \
  build/android/jniLibs/arm64-v8a/libtravonet-wg.so | grep ' Java_'
```

---

## Лицензия

MIT. Исходный код основан на wireguard-go (WireGuard LLC, 2017–2025).
