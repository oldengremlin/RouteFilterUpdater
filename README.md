# RouteFilterUpdater

RouteFilterUpdater — утиліта на Java для автоматизації створення та застосування BGP-маршрутних фільтрів на маршрутизаторах Juniper. Зчитує конфігурацію BGP-сусідів з роутера через SSH, отримує дані про маршрути з IRR через WHOIS, генерує фільтри за допомогою **bgpq4** у форматі Junos і застосовує конфігурацію через `load merge terminal`. Підтримує IPv4 та IPv6, веде логування та надсилає звіти електронною поштою.

## Можливості

- **bgpq4** як єдиний інструмент генерації фільтрів — виводить готовий Junos-формат з `replace:` маркерами.
- **Один WHOIS-запит** на запуск — для SELF_AS, результат кешується в пам'яті; окремих запитів для кожного сусіда немає.
- **Паралельна генерація** — до 6 викликів bgpq4 одночасно на віртуальних потоках (JDK 21); порядок виводу зберігається.
- **Підтримка IPv4 та IPv6** — окремі BGP-групи й маршрутні фільтри для кожного сімейства адрес.
- **Застосування через `load merge terminal`** — без покомандної відправки `delete/set`, конфігурація завантажується одним блоком.
- **Блокування через `FileLock`** — запобігає одночасному запуску кількох екземплярів; ОС звільняє блокування навіть після `kill -9`, тож «застряглих» lock-файлів не буває.
- **Ізоляція збоїв** — помилка bgpq4 на одному фільтрі не зриває весь запуск і не відправляє на роутер урізаний список префіксів.
- **Надсилання звітів** електронною поштою з результатами `show | compare` — зокрема й тоді, коли застосування провалилось.

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
| `--rpsl-proposal` | Автономний режим перевірки узгодженості RPSL: для кожного активного сусіда в BGP-групі зіставляє `export` peer-а з нашим `import`; виводить пропозиції оновлених `mp-import` рядків при розбіжностях. Не генерує фільтри і не застосовує конфігурацію. |
| `-h, --help` | Показати довідку |

Невідома опція або опція без обов'язкового значення (`-o`, `--sqlite`) — помилка запуску, а не мовчазне ігнорування.

### Коди виходу

| Код | Значення |
|---|---|
| `0` | Успіх |
| `1` | Фатальна помилка: конфігурація, роутер недоступний, працює інший екземпляр, провал `commit` |
| `2` | Завершено з проблемами: частина фільтрів не згенерувалась, або `--rpsl-proposal` знайшов розбіжності |

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
├── RouteFilterUpdater.java   — точка входу, оркестрація, коди виходу, FileLock
├── Args.java                 — розбір і валідація аргументів командного рядка
├── Config.java               — завантаження RouteFilterUpdater.properties
├── AddressFamily.java        — enum V4/V6: мітка, RPSL afi, назва Junos-терму
├── BgpNeighbor.java          — record: ip, peerAs, importPolicy
├── WhoisPolicy.java          — набори маршрутів на peer AS (окремо IPv4 / IPv6)
├── GenerateResult.java       — record: фільтри, анотовані фільтри, попередження, лічильники
├── SshClient.java            — JSch: exec-канал + PTY shell з waitForPrompt
├── RouterClient.java         — Junos SSH: getNeighbors + applyFilters
├── NeighborLoader.java       — спільне завантаження сусідів з роутера
├── JunosOutput.java          — спільні патерни очищення виводу термінала
├── WhoisFetcher.java         — WHOIS / SQLite + розбір RPSL (import/export)
├── Bgpq4Client.java          — виклик bgpq4 як зовнішнього процесу
├── FilterGenerator.java      — головна бізнес-логіка генерації фільтрів
├── RpslProposalRunner.java   — автономна перевірка узгодженості RPSL
└── EmailReporter.java        — надсилання SMTP-звітів

src/test/java/net/ukrcom/routefilterupdater/
└── WhoisFetcherTest.java     — тести розбору RPSL (28 тестів, без мережі)
```

### Розбір RPSL

Розбір відповідає RFC 2622 і навмисно не є одним монолітним регексом: рядок ділиться
за ключовим словом `accept` / `announce`, ліва частина дає `afi` та перелік peer-ів,
права — вираз-фільтр. Завдяки цьому коректно обробляються:

- список `afi` через кому: `afi ipv4.unicast, ipv6.unicast from AS1 accept AS-X`
- клауза `at`: `import: from AS1 at 1.2.3.4 action pref=100; accept AS-X`
- кілька `from` в одному рядку
- рядки-продовження (починаються з пробілу, табуляції або `+`)
- **заперечення**: у `accept NOT AS-BAD AND AS-GOOD` береться `AS-GOOD`, а не `AS-BAD`
- **віднімання**: `accept AS-A EXCEPT AS-B` дає лише `AS-A`
- **кілька наборів**: `accept AS-A OR AS-B` дає обидва (bgpq4 приймає їх одним викликом)

#### Межі розбору

Це **не** повна реалізація граматики RPSL, а цілеспрямований екстрактор: єдине питання,
на яке він відповідає — «які AS-SET передати в bgpq4 для цього peer-а й сімейства адрес».
Розгортанням самих наборів займається bgpq4.

Свідомо не підтримується (такі політики пропускаються без генерації фільтра, з записом у лог):

- явні списки префіксів: `accept { 192.0.2.0/24^24-32 }`
- регулярні вирази AS-path: `accept <^AS1 AS2+ AS3*$>`
- фільтри за community / origin: `accept community(65000:1)`
- композиція `refine` та протокольні кваліфікатори `protocol BGP4 into RIP`
- пріоритет операторів: `AND` формально зв'язує сильніше за `OR`, тут вираз обробляється пласко

Жоден із цих випадків не виражається аргументом bgpq4, тож пропуск — безпечна поведінка:
наявний фільтр на роутері лишається без змін.

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

**`--rpsl-proposal`** — автономний режим (фільтри не генеруються, до роутера не підключається). Зчитує активних сусідів із BGP-групи, для кожного peer-а запитує його WHOIS і зіставляє `export` з нашим `import`. Виводить лише відхилення:

Розбіжність між нашим `import` і `export` peer-а:
```
[MISMATCH]  AS42545 [212.90.185.30] ASTARTA
  our import:   AS-SYNCHRON
  peer exports: AS-SYNCHRON-PEERS
  proposed: mp-import: afi ipv4.unicast from AS42545 accept AS-SYNCHRON-PEERS
```

У нас немає `import` для цього peer-а, але peer оголошує конкретний набір:
```
[MISSING]   AS99999 [1.2.3.4]
  we have no IPv4 import for this peer in AS12593 WHOIS
  peer exports: AS99999
  proposed: mp-import: afi ipv4.unicast from AS99999 accept AS99999
```

Peer оголошує `ANY`:
```
[WARNING]   AS41600 [5.6.7.8]
  peer exports ANY to AS12593 — no specific prefix set declared
```

Peer не має жодного запису `export` до нас:
```
[NO-EXPORT] AS77777 [9.9.9.9]
  peer has no IPv4 export to AS12593 in WHOIS
```

Запит до WHOIS не вдався:
```
[ERROR]     AS88888 [7.7.7.7]
  WHOIS lookup failed: Connection timed out
```

Приватні номери AS (RFC 6996: `64512–65534`, `4200000000–4294967294`) позначаються префіксом `[PRIVATE]`.

Збіги — мовчки. Підсумок у останньому рядку:
```
--- IPv4: 42 checked, 35 matched, 4 mismatched/missing, 2 ANY warnings, 1 no-export
```

Вивід іде в stdout; щоб зберегти у файл — перенаправте оболонкою:
```bash
java -jar RouteFilterUpdater-1.0-all.jar --rpsl-proposal -4 --sqlite /var/db/whoislitelocal.db > rpsl-proposals.txt
```

## Логування

- Логи пишуться у `logs/routefilterupdater.log` (rolling, 10 МБ / 30 днів / 1 ГБ).
- `-d` — debug-рівень для діагностики SSH і bgpq4.
- `-q` — вимикає вивід у консоль (файловий лог продовжує писатись).

## Ліцензія

Проєкт ліцензовано за [Apache License 2.0](LICENSE).

## Контакти

Для повідомлень про проблеми або запитань відкривайте [issue](https://github.com/oldengremlin/RouteFilterUpdater/issues) на GitHub.
