import os
import re

# Папки которые считаем — добавляй по мере появления новых тем
TOPICS = {
    "SQL Injection": "portswigger/sqli",
    "XSS":           "portswigger/xss",
    "CSRF":          "portswigger/csrf",
    "SSRF":          "portswigger/ssrf",
    "JWT":           "portswigger/jwt",
    "CORS":          "portswigger/cors",
}

def count_files(folder: str) -> int:
    if not os.path.exists(folder):
        return 0
    return len([f for f in os.listdir(folder) if f.endswith(".md")])

def build_table() -> str:
    rows = []
    total = 0

    for topic, folder in TOPICS.items():
        count = count_files(folder)
        total += count
        if count > 0:  # показываем только непустые темы
            rows.append(f"| {topic} | {count} |")

    rows.append(f"| **Всего** | **{total}** |")

    header = "| Тема | Количество write-ups |\n|---|---|"
    return header + "\n" + "\n".join(rows)

def update_readme():
    with open("README.md", "r", encoding="utf-8") as f:
        content = f.read()

    new_table = build_table()

    # Заменяем блок между маркерами
    pattern = r"(<!-- WRITEUPS_START -->).+?(<!-- WRITEUPS_END -->)"
    replacement = f"<!-- WRITEUPS_START -->\n{new_table}\n<!-- WRITEUPS_END -->"

    updated = re.sub(pattern, replacement, content, flags=re.DOTALL)

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(updated)

    print("README.md обновлён")

if __name__ == "__main__":
    update_readme()