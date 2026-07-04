# RouteFilterUpdater

RouteFilterUpdater — утиліта на Java для автоматизації створення та застосування BGP-маршрутних фільтрів на маршрутизаторах Juniper. Зчитує конфігурацію BGP-сусідів з роутера через SSH, отримує дані про маршрути з IRR через WHOIS, генерує фільтри за допомогою **bgpq4** у форматі Junos і застосовує конфігурацію через `load merge terminal`. Підтримує IPv4 та IPv6, веде логування та надсилає звіти електронною поштою.

## Можливості

- **bgpq4** як єдиний інструмент генерації фільтрів — виводить готовий Junos-формат з `replace:` маркерами.
- **Один WHOIS-запит** на запуск — для SELF_AS, результат кешується в пам'яті; окремих запитів для кожного сусіда немає.
- **Підтримка IPv4 та IPv6** — окремі BGP-групи й маршрутні фільтри для кожного сімейства адрес.
- **Застосування через `load merge terminal`** — без покомандної відправки `delete/set`, конфігурація завантажується одним блоком.
- **Механізм блокування** — запобігає одночасному запуску кількох екземплярів.
- **Надсилання звітів** електронною поштою з результатами `show | compare`.

## Вимоги

- **Java 21** або вище.
- **Maven** — для збирання проєкту.
- **bgpq4** — встановлений та доступний за шляхом у `BGPQ4_PATH` ([github.com/bgp/bgpq4](https://github.com/bgp/bgpq4)).
- **Маршрутизатор Juniper** з увімкненим SSH-доступом.
- **WHOIS-сервер** (за замовчуванням `whois.ripe.net`).
- **SMTP-сервер** — опціонально, для надсилання звітів.

### Java-залежності (зшиваються у fat JAR автоматично)

- JSch — SSH-клієнт
- Apache Commons Net — WHOIS-клієнт
- SLF4J + Logback — логування
- JavaMail — надсилання звітів

## Встановлення

1. **Клонування репозиторію**:

   ```bash
   git clone git@github.com:oldengremlin/RouteFilterUpdater.git
   cd RouteFilterUpdater
   ```

2. **Збирання проєкту**:

   ```bash
   mvn clean package
   ```

   Результат: `target/RouteFilterUpdater-1.0-all.jar`

3. **Налаштування конфігурації**: Створіть `RouteFilterUpdater.properties` поряд із JAR-файлом:

   ```properties
   # --- Роутер ---
   ROUTER_IP=94.125.120.65
   ROUTER_IP_IPV6=2a04:42c0::1

   # --- SSH ---
   USERNAME=noc
   # PASSWORD=... або задайте змінну середовища ROUTER_PASSWORD

   # --- BGP ---
   SELF_AS=AS12593
   BGP_GROUP_IPV4=Clients
   BGP_GROUP_IPV6=Clients6

   # Регулярні вирази (через кому) для виключення певних import-policy зі списку сусідів
   EXCEPT_REGEX=Client_world_uaix_in,Client_PFTS_in,TE_IN,RPKI-MARK

   # --- bgpq4 ---
   BGPQ4_PATH=/usr/local/bin/bgpq4
   # Список IRR-баз для bgpq4 -S (опціонально)
   BGPQ4_SOURCES=RADB,RIPE,APNIC,ARIN

   # --- WHOIS (для запиту SELF_AS) ---
   WHOIS_SERVER=whois.radb.net

   # --- Email-звіти (опціонально) ---
   SMTP_HOST=your-smtp-server
   SMTP_PORT=587
   SMTP_USER=your-smtp-user
   SMTP_PASS=your-smtp-password
   REPORT_FROM=noc@example.com
   REPORT_TO=admin@example.com

   DEBUG=false
   ```

   > **Безпека**: задайте пароль через змінну середовища `ROUTER_PASSWORD`, а не в properties-файлі.

4. **Встановлення bgpq4**:

   ```bash
   # Debian/Ubuntu
   apt install bgpq4

   # або з вихідників
   git clone https://github.com/bgp/bgpq4.git && cd bgpq4 && ./configure && make install
   ```

## Використання

```bash
java -jar target/RouteFilterUpdater-1.0-all.jar [опції]
```

### Опції

| Опція | Опис |
|---|---|
| `-4` | Генерувати фільтри для IPv4 (за замовчуванням) |
| `-6` | Генерувати фільтри для IPv6 |
| `-o <файл>` | Зберегти фільтри у файл (без `-o` та `-s` — вивід у stdout) |
| `-s, --save` | Застосувати конфігурацію до роутера через SSH |
| `-r, --report` | Надіслати звіт на `REPORT_TO` |
| `-d, --debug` | Детальне логування |
| `-q, --quiet` | Без виводу в консоль (для cron) |
| `--sqlite <файл>` | Використовувати локальну SQLite БД для WHOIS-запитів; якщо AS не знайдено — fallback на живий WHOIS |
| `--strict-rpsl` | Виводити попередження на stderr, якщо у peer RPSL-політика `accept ANY` |
| `--strict-rpsl-reverse` | Перевіряти WHOIS peer-а: чи збігається його `export` до нас із тим, що ми очікуємо; виводити попередження при розбіжності (один додатковий WHOIS-запит на peer) |
| `-h, --help` | Показати довідку |

### Приклади

```bash
# Переглянути згенеровані IPv4-фільтри без застосування
java -jar RouteFilterUpdater-1.0-all.jar -4

# Зберегти IPv4-фільтри у файл, застосувати та надіслати звіт
java -jar RouteFilterUpdater-1.0-all.jar -4 -o filters-v4.txt -s -r

# IPv6-фільтри у тихому режимі (для cron)
java -jar RouteFilterUpdater-1.0-all.jar -6 -s -r -q
```

## Як це працює

```
1. WHOIS(SELF_AS) → Map<peerAs → {ipv4Set, ipv6Set}>   # один запит, in-memory кеш

2. SSH → show configuration protocols bgp group <GROUP>
         | display set | match "(import|peer-as)"
         | except "<EXCEPT_REGEX>"
   → List<BgpNeighbor(ip, peerAs, importPolicy)>

3. Для кожної унікальної importPolicy:
     acceptSet = whoisMap[peerAs].ipv4Set  (або ipv6Set для -6)
     якщо acceptSet == ANY → пропустити (дозволяємо все, фільтр не потрібен)
     termName  = "accept" (IPv4) або "accept_v6" (IPv6)
     bgpq4 -AJEl <importPolicy>/<termName> <acceptSet>  [-6]

4. Об'єднаний вивід → файл / stdout

5. Якщо -s:
     SSH shell → configure private
               → load merge terminal
               → [вміст фільтрів] + Ctrl+D
               → show | compare | no-more
               → commit and-quit
                   ├─ успіх → operational prompt → готово
                   └─ помилка (error: ...) → rollback 0 → exit → виняток
```

## Формат виводу (bgpq4 -J -E)

Готовий Junos-блок з `replace:` для `load merge terminal`:

IPv4 (`-4`):
```
policy-options {
 policy-statement Client_plf_SINHRON {
  term accept {
replace:
   from {
    route-filter 91.201.36.0/22 exact;
    route-filter 91.209.126.0/24 exact;
    route-filter 195.138.218.0/24 exact;
   }
  }
 }
}
```

IPv6 (`-6`) — термін `accept_v6`:
```
policy-options {
 policy-statement Client_plf_CLOUD_NETS {
  term accept_v6 {
replace:
   from {
    route-filter 2001:470:177::/48 exact;
    route-filter 2a09:2dc2::/32 exact;
   }
  }
 }
}
```

## Структура коду

```
src/main/java/net/ukrcom/routefilterupdater/
├── RouteFilterUpdater.java   — точка входу, оркестрація
├── Args.java                 — розбір аргументів командного рядка
├── Config.java               — завантаження RouteFilterUpdater.properties
├── BgpNeighbor.java          — дата-клас: ip, peerAs, importPolicy
├── WhoisPolicy.java          — дата-клас: ipv4Set / ipv6Set на peer AS
├── SshClient.java            — JSch: exec-канал + PTY shell з waitForPrompt
├── RouterClient.java         — Junos SSH: getNeighbors + applyFilters
├── WhoisFetcher.java         — WHOIS-запит + парсинг mp-import/import рядків
├── Bgpq4Client.java          — виклик bgpq4 як зовнішнього процесу
├── FilterGenerator.java      — головна бізнес-логіка генерації фільтрів
└── EmailReporter.java        — надсилання SMTP-звітів
```

## Міграція з попередньої версії (rtconfig)

| Стара властивість | Нова властивість | Примітка |
|---|---|---|
| `RTCONFIG_PATH=...` | `BGPQ4_PATH=...` | Вказати шлях до bgpq4 |
| `IRR_SOURCES=...` | `BGPQ4_SOURCES=...` | Стара назва також приймається |
| `IRR_CACHE_FILE=...` | *(видалити)* | Файл кешу більше не використовується |
| `WHOIS_OPTIONS=-r` | *(видалити)* | Хардкод у WhoisFetcher |
| `SMTP_SERVER=...` | `SMTP_HOST=...` | Стара назва також приймається |
| `SMTP_PASSWORD=...` | `SMTP_PASS=...` | Стара назва також приймається |

## Локальна SQLite БД (`--sqlite`)

Опція дозволяє замінити мережеві WHOIS-запити на запити до локальної SQLite БД, сформованої проєктом [whois-lite-local](https://github.com/oldengremlin/whois-lite-local) (оновлюється раз на добу з публічних файлів RIR).

```bash
java -jar RouteFilterUpdater-1.0-all.jar -4 -s --sqlite /var/db/whoislitelocal.db
```

**Логіка:**
1. Якщо `--sqlite` задано → запит до таблиці `rpsl` (де `key='aut-num'`) за AS-номером
2. Запис знайдено → парсимо поле `block` (той самий формат, що й відповідь живого WHOIS)
3. Запис **не знайдено** → fallback на живий WHOIS-сервер
4. Помилка відкриття/запиту БД → попередження в лог + fallback на живий WHOIS

**Переваги:** значно швидше (особливо з `--strict-rpsl-reverse`, де запитів N=кількість peers), менше навантаження на WHOIS-сервери RIPE.

**Обмеження:** БД оновлюється раз на добу; зміни в RIPE DB будуть видимі лише після наступного оновлення.

## RPSL-діагностика

Обидві опції виводять попередження на **stderr** (завжди, навіть із `-q`). При наявності `-r` попередження також потрапляють у розділ `=== RPSL Warnings ===` email-звіту.

**`--strict-rpsl`** — спрацьовує, коли наша AS очікує від peer-а `accept ANY`:
```
WARNING: AS41600 is described in your import policy as "accept ANY".
No prefix filter generated for Client_plf_SINHRON.
Verify whether this is intentional or an incomplete RPSL description.
```

**`--strict-rpsl-reverse`** — для кожного peer-а робить окремий WHOIS-запит і порівнює, що peer оголошує нам (`export: to AS<SELF_AS> announce <set>`) з тим, що ми від нього очікуємо. Варіанти:

Розбіжність (peer каже `ANY`, ми очікуємо `AS-SYNCHRON`):
```
RPSL-REVERSE WARNING: AS41600 export to AS12593 declares "ANY" but your import policy expects "AS-SYNCHRON".
Verify that the RPSL records in both AS objects are consistent.
```

Запис відсутній у WHOIS peer-а:
```
RPSL-REVERSE WARNING: AS41600 has no export to AS12593 in WHOIS.
Your import policy expects "AS-SYNCHRON" — the peer's RPSL may be incomplete.
```

Збіг (`export: to AS12593 announce AS57341` і ми очікуємо `AS57341`) — мовчки, без попередження.

## Логування

- Логи пишуться у `logs/routefilterupdater.log` (rolling, 10 МБ / 30 днів / 1 ГБ).
- `-d` — debug-рівень для діагностики SSH і bgpq4.
- `-q` — вимикає вивід у консоль (файловий лог продовжує писатись).

## Ліцензія

Проєкт ліцензовано за [Apache License 2.0](LICENSE).

## Контакти

Для повідомлень про проблеми або запитань відкривайте [issue](https://github.com/oldengremlin/RouteFilterUpdater/issues) на GitHub.
