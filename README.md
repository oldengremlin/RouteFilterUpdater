# RouteFilterUpdater

RouteFilterUpdater — це утиліта на Java для автоматизації створення та застосування BGP-маршрутних фільтрів на маршрутизаторах Juniper. Вона отримує інформацію про BGP-сусідів, запитує бази IRR (Internet Routing Registry), генерує маршрутні фільтри на основі даних WHOIS і застосовує конфігурацію до маршрутизатора через SSH. Підтримує IPv4 та IPv6, включає логування та надсилання звітів про виконання електронною поштою.

## Можливості

- **Автоматизація маршрутних фільтрів**: Генерує BGP-фільтри на основі даних IRR і конфігурації BGP-сусідів.
- **Підтримка маршрутизаторів Juniper**: Застосовує конфігурації через SSH і Junos CLI.
- **Сумісність з IPv4 та IPv6**: Генерує фільтри для обох типів адрес.
- **Інтеграція з IRR**: Виконує запити до WHOIS-серверів (наприклад, RADB) для отримання даних про піринг і експорт.
- **Звіти про виконання**: Надсилає детальні звіти електронною поштою з інформацією про зміни конфігурації.
- **Обробка помилок**: Включає повторні спроби для WHOIS-запитів і SSH-команд із детальним логуванням.
- **Валідація конфігурації**: Перевіряє файли IRR і застосовує лише валідні префікси.
- **Механізм блокування**: Запобігає одночасному запуску кількох екземплярів.

## Вимоги

- **Java**: Java 8 або вище.
- **Maven**: Для збирання проєкту.
- **Маршрутизатор Juniper**: З увімкненим доступом через SSH.
- **Доступ до WHOIS-сервера**: Наприклад, `whois.radb.net`.
- **SMTP-сервер**: (Опціонально) Для надсилання звітів.
- **Залежності**:
  - JSch (для SSH)
  - Apache Commons Net (для WHOIS)
  - SLF4J з Logback (для логування)
  - JavaMail (для надсилання звітів)

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

   Це створить `target/RouteFilterUpdater-1.0-all.jar`.

3. **Налаштування конфігурації**: Створіть файл `RouteFilterUpdater.properties` у корені проєкту з такими налаштуваннями:

   ```properties
   ROUTER_IP=your-router-ip
   USERNAME=your-username
   PASSWORD=your-password
   BGP_GROUP=Clients
   SELF_AS=AS12593
   IRR_CACHE_FILE=as12593_irr_objects.txt
   EXCEPT_REGEX=Client_world_uaix_in,Client_PFTS_in,TE_IN
   IRR_SOURCES=RADB,RIPE,APNIC,ARIN,LACNIC,AFRINIC
   RTCONFIG_PATH=/usr/local/bin/rtconfig
   WHOIS_SERVER=whois.radb.net
   WHOIS_OPTIONS=-r
   SMTP_SERVER=your-smtp-server
   SMTP_PORT=25
   SMTP_USER=your-smtp-user
   SMTP_PASSWORD=your-smtp-password
   REPORT_TO=recipient@example.com
   REPORT_FROM=sender@example.com
   DEBUG=false
   ```

   Альтернативно, задайте `ROUTER_PASSWORD` як змінну середовища, щоб не зберігати пароль у файлі.

4. **Встановлення rtconfig**: Переконайтеся, що утиліта `rtconfig` встановлена та доступна за шляхом, указаним у `RTCONFIG_PATH`.

## Використання

Запустіть утиліту командою:

```bash
java -jar target/RouteFilterUpdater-1.0-all.jar [опції]
```

### Опції

- `-4`: Генерувати фільтри для IPv4 (за замовчуванням).
- `-6`: Генерувати фільтри для IPv6.
- `-o <файл>`: Зберегти фільтри у вказаний файл.
- `-d, --debug`: Увімкнути детальне логування.
- `-s, --save`: Застосувати згенеровану конфігурацію до маршрутизатора.
- `-r, --report`: Надіслати звіт про виконання на адресу, указану в `REPORT_TO`.
- `-q, --quiet`: Придушити вивід у консоль (зручно для cron).
- `-?, -h, --help`: Показати довідку.

### Приклад

Генерація фільтрів IPv4, збереження у файл, застосування до маршрутизатора та надсилання звіту:

```bash
java -jar target/RouteFilterUpdater-1.0-all.jar -o ukrcom-gw-route-filter-updater.txt -s -r -d
```

## Формат конфігураційного файлу

Вихідний файл (наприклад, `ukrcom-gw-route-filter-updater.txt`) містить команди конфігурації Junos, наприклад:

```
delete policy-options policy-statement Client_plf_OPERATOR_RINKA_NEW_AS term accept from
set policy-options policy-statement Client_plf_OPERATOR_RINKA_NEW_AS term accept from route-filter 94.45.144.0/24 exact accept
```

Коментарі, що починаються з `#`, ігноруються під час застосування.

## Логування

- Логи записуються у тимчасовий файл (`routefilterupdater-session-<UUID>.log`).
- Режим дебагу (`-d`) забезпечує детальні логи для діагностики.
- Старі логи (старші 7 днів) автоматично видаляються.

## Звіти електронною поштою

При використанні опції `-r` утиліта надсилає звіт на адресу, указану в `REPORT_TO`. Звіт містить:

- Зміни конфігурації (вивід `show | compare`).
- Статус виконання.

Приклад звіту:

```
RouteFilterUpdater report:

RouteFilterUpdater Configuration Changes:

[edit]
-  # 2025-04-23T10:50:13+03:00
+  # 2025-04-23T10:50:59+03:00
```

## Ліцензія

Проєкт ліцензовано за [Apache License 2.0](LICENSE).

## Контакти

Для повідомлень про проблеми або запитань відкривайте [issue](https://github.com/oldengremlin/RouteFilterUpdater/issues) на GitHub або звертайтеся до maintainer’а за адресою \[olden@ukr-com.net\].