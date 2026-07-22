import re
from pathlib import Path

# Папки которые считаем — добавляй по мере появления новых тем
TOPICS = {
    "SQL Injection": ["portswigger/sqli"],
    "XSS":           ["portswigger/xss"],
    "CSRF":          ["portswigger/csrf", "rootme/csrf"],
    "SSRF":          ["portswigger/ssrf"],
    "JWT":           ["portswigger/jwt"],
    "CORS":          ["portswigger/cors"],
    "Access Control":["portswigger/bac"]
}

def count_files(folders: list[str]) -> int:
    count = 0

    for folder in folders:
        path = Path(folder)
        if not path.exists():
            continue

        count += sum(1 for file in path.iterdir() if file.suffix == ".md")

    return count

def build_table() -> str:
    rows = []
    total = 0

    for topic, folders in TOPICS.items():
        count = count_files(folders)
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