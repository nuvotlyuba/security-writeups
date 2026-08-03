# 📝 Security Write-ups

Разборы уязвимостей и решения лабораторных по веб-безопасности.

---

## Платформы
- [PortSwigger Web Security Academy](./portswigger/)
- [Root Me](./rootme/)

---

## Прогресс

<!-- WRITEUPS_START -->
| Тема | Количество write-ups |
|---|---|
| SQL Injection | 17 |
| NoSQL Injection | 3 |
| XSS | 8 |
| XXE | 6 |
| CSRF | 9 |
| SSRF | 7 |
| JWT | 1 |
| Business Logic | 1 |
| Unrestricted File Upload | 0 |
| Race Condition | 1 |
| Insecure Deserialization | 3 |
| Access Control | 10 |
| **Всего** | **66** |
<!-- WRITEUPS_END -->

---

## Структура

```
security-writeups/
├── rootme/
|   ├── sqli/
|   ├── nosqli/
|   ├── file_upload/
|   └── csrf/
├── portswigger/
│   ├── sqli/
|   ├── nosqli/
|   ├── csrf/
|   ├── xxe/
|   ├── ssrf/
|   ├── race_condition/
|   ├── file_upload/
|   ├── business_logic/
|   ├── insecure_deserialization/
|   ├── bac/
|   ├── jwt/
│   └── xss/
└── scripts/
    └── count_writeups.py
```