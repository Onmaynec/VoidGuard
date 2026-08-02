<div align="center">

**CYBERPUNK WINDOWS THREAT ANALYSIS CONSOLE**  
PowerShell 5.1+ · Windows 10/11 · defensive security toolkit

[![CI](https://github.com/Onmaynec/VoidGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Onmaynec/VoidGuard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Onmaynec/VoidGuard?display_name=tag)](https://github.com/Onmaynec/VoidGuard/releases)
[![License](https://img.shields.io/badge/license-MIT-00ff77)](LICENSE)

</div>

## Что это

**VoidGuard** — консольная Windows-утилита для проверки подозрительных файлов, процессов, автозапуска и состояния встроенной защиты. Интерфейс стилизован под «хакерскую» панель: ASCII/Unicode-арт, glitch-эффекты, цветные статусы, fake-code и анимированная загрузка `▰▰▰▰▰▰▰▰▰▰ 100%`.

При этом реальные результаты не смешиваются с декорацией: фейковые эффекты всегда помечены `[VISUAL]`.

## Возможности v0.1.0

- меню с управлением стрелками;
- cinematic и professional режимы;
- Quick Scan стандартных пользовательских зон;
- сканирование выбранного файла или каталога;
- SHA-256 и Authenticode;
- двойные расширения и маскировка под системные процессы;
- опасные PowerShell/VBS/JS-паттерны;
- инспектор процессов и автозапуска;
- Defender, Firewall и UAC status;
- защищённый карантин и восстановление;
- JSON-вывод для автоматизации.

## Установка

Скачайте `VoidGuard-v0.1.0-Portable.zip` из **Releases**, распакуйте и запустите:

```cmd
VoidGuard.cmd
```

Для ручного запуска:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\VoidGuard.ps1
```

## Безопасность удаления

VoidGuard v0.1.0 **не является универсальным удалятором**. Карантин блокируется для Windows, Program Files, WRP, Microsoft-signed и TrustedInstaller файлов, а также ссылок/reparse points. Занятый процессом файл не удаляется: утилита показывает PID и предлагает закрыть процесс вручную.

Эти ограничения нельзя отключить `--force`.

## CLI

```powershell
.\VoidGuard.ps1 -Mode QuickScan -Professional
.\VoidGuard.ps1 -Mode CustomScan -Path "C:\Downloads" -Json
.\VoidGuard.ps1 -Mode Status -Json
.\VoidGuard.ps1 -Mode Demo
```

Подробности: [docs/USAGE.md](docs/USAGE.md) и [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Важное предупреждение

VoidGuard — дополнительный диагностический инструмент, а не замена Microsoft Defender или коммерческому EDR. Эвристические результаты могут содержать ложные срабатывания. Проверяйте путь, подпись, хеш и причины оценки перед карантином.

## Roadmap

- **v0.2** — Services, Scheduled Tasks, HTML/JSON reports;
- **v0.3** — YARA и подписываемые rule packs;
- **v0.4** — безопасное удаление после перезагрузки;
- **v1.0** — стабильный CLI и автоматические обновления правил.

## Лицензия

MIT. Используйте только для законной защиты и анализа собственных систем.
