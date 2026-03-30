<p align="center">
  <img src="docs/logo.jpg" alt="TeleGO Logo" width="200">
</p>

<h1 align="center">TeleGO</h1>

<p align="center">
  <strong>Высокопроизводительный Telegram MTProxy на Go с TLS-маскировкой</strong>
</p>

<p align="center">
  <a href="README.md">English</a> •
  <a href="#возможности">Возможности</a> •
  <a href="#быстрый-старт">Быстрый старт</a> •
  <a href="#конфигурация">Конфигурация</a> •
  <a href="#docker">Docker</a>
</p>

---

> **Telegram заблокирован?** TLS-маскировка TeleGO делает ваш прокси неотличимым от обычного HTTPS-трафика для цензоров. [Настройка за 2 минуты](#быстрый-старт)

---

## Почему TeleGO?

| Функция | TeleGO | mtg | Официальный MTProxy |
|---------|:------:|:---:|:-------------------:|
| TLS-маскировка | Да | Да | Нет |
| Защита от проб | Да | Да | Нет |
| Метрики по пользователям | Да | Нет | Нет |
| Лимит IP на пользователя | Да | Нет | Нет |
| Умная блокировка IP | Да | Нет | Нет |
| Защита от OOM | Да | Нет | Нет |
| Горячая перезагрузка | Да | Да | Нет |
| Поддерживается (2026) | Да | Частично | Нет |

---

## Возможности

### Сеть
- **Event-driven I/O** — на базе [gnet](https://github.com/panjf2000/gnet) с epoll/kqueue
- **Zero-copy** — прямая работа с буферами без копирования
- **Пул буферов** — отсутствие аллокаций в горячих путях
- **Оптимизированный TCP** — `TCP_NODELAY`, `TCP_QUICKACK`, буферы 64KB

### Безопасность
- **TLS-маскировка** — получает реальные сертификаты от маскирующего хоста
- **Защита от проб** — нераспознанные клиенты перенаправляются на маскирующий хост
- **Защита от replay-атак** — 64-шардовый LRU-кэш с TTL
- **Обнуление ключей** — чувствительные данные обнуляются при закрытии соединения

### Эксплуатация
- **Мульти-пользователь** — именованные секреты с отслеживанием по пользователям
- **Лимиты подключений** — ограничение IP на пользователя с умной блокировкой
- **Prometheus-метрики** — статистика подключений и трафика по пользователям
- **Горячая перезагрузка** — SIGHUP и отслеживание изменений файла конфигурации
- **SOCKS5 upstream** — маршрутизация через SOCKS5 (Hysteria2, VLESS и др.)

---

## Быстрый старт

**1. Сгенерируйте секрет:**

```bash
telego generate www.google.com
# secret=0123456789abcdef0123456789abcdef  <- в конфиг
# link=tg://proxy?server=...               <- ссылка для клиентов
```

**2. Создайте `config.toml`:**

```toml
[general]
bind-to = "0.0.0.0:443"

[secrets]
alice = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "www.google.com"
```

**3. Запустите:**

```bash
telego run -c config.toml -l
```

Флаг `-l` выводит ссылки для Telegram с автоопределением публичного IP.

---

## Конфигурация

```toml
[general]
bind-to = "0.0.0.0:443"
log-level = "info"

# Защита от абьюза
max-connections-per-ip = 100  # Макс. подключений с одного IP
max-ips-per-user = 3          # Макс. IP на один секрет
ip-block-timeout = "5m"       # Время блокировки IP

[secrets]
user1 = "0123456789abcdef0123456789abcdef"
user2 = "fedcba9876543210fedcba9876543210"

[tls-fronting]
mask-host = "www.google.com"
# splice-host = "127.0.0.1"   # Куда перенаправлять нераспознанных клиентов
# splice-port = 8080

[performance]
prefer-ip = "prefer-ipv4"
idle-timeout = "5m"

[upstream]
# socks5 = "127.0.0.1:1080"   # Upstream через SOCKS5

[metrics]
bind-to = "127.0.0.1:9090"
```

---

## Docker

```bash
docker run -d \
  --name telego \
  -p 443:443 \
  -v /path/to/config.toml:/config.toml \
  scratchnet/telego:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  telego:
    image: scratchnet/telego:latest
    restart: unless-stopped
    ports:
      - "443:443"
    volumes:
      - ./config.toml:/config.toml:ro
```

---

## Установка

### Из исходников

```bash
git clone https://github.com/Scratch-net/telego.git
cd telego
make build
```

### Готовые бинарники

Скачайте с [Releases](https://github.com/Scratch-net/telego/releases/latest).

### Go Install

```bash
go install github.com/scratch-net/telego/cmd/telego@latest
```

---

## Метрики

| Метрика | Тип | Описание |
|---------|-----|----------|
| `telego_connections_active` | Gauge | Активные подключения |
| `telego_ips_active` | Gauge | Уникальные IP |
| `telego_ips_blocked` | Gauge | Заблокированные IP |
| `telego_blocked_total` | Counter | Всего блокировок |
| `telego_traffic_in_bytes_total` | Counter | Входящий трафик |
| `telego_traffic_out_bytes_total` | Counter | Исходящий трафик |

Все метрики имеют лейбл `user` для разбивки по пользователям.

---

## Лицензия

[Apache License 2.0](LICENSE)

---

## Благодарности

- **[mtg](https://github.com/9seconds/mtg)** — оригинальная Go-реализация MTProxy
- **[mtprotoproxy](https://github.com/alexbers/mtprotoproxy)** — Python референсная реализация
- **[telemt](https://github.com/nicksnet/telemt)** — высокопроизводительная Rust-реализация
