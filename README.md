<div align="center">

# VOIDGUARD

**CYBERPUNK WINDOWS THREAT ANALYSIS & REMEDIATION CONSOLE**  
PowerShell 5.1+ · Windows 10/11 · defensive security toolkit

[![CI](https://github.com/Onmaynec/VoidGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Onmaynec/VoidGuard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Onmaynec/VoidGuard?display_name=tag)](https://github.com/Onmaynec/VoidGuard/releases)
[![License](https://img.shields.io/badge/license-MIT-00ff77)](LICENSE)

`[ SCAN ]  [ ANALYZE ]  [ CONTAIN ]  [ VERIFY ]`

</div>

## Что это

**VoidGuard** — консольная Windows-утилита для проверки подозрительных файлов, процессов, механизмов закрепления и состояния встроенной защиты. Интерфейс стилизован под хакерскую панель: Unicode-арт, glitch-эффекты, цветные статусы, fake-code, tree-анимации и загрузка `▰▰▰▰▰▰▰▰▰▰ 100%`.

Декорация отделена от реальных результатов: фейковые эффекты всегда помечаются `[VISUAL]` и никогда не участвуют в решении об угрозе.

## Возможности v0.2.0 — LOCKDOWN PROTOCOL

- полноэкранное TUI-меню с управлением стрелками;
- Quick Scan и сканирование выбранного файла/каталога;
- SHA-256, Authenticode, двойные расширения и скриптовые эвристики;
- анализ процессов: путь, подпись, командная строка, parent PID и TCP-соединения;
- `PERSISTENCE MATRIX`: Run/RunOnce, Startup folders, Services, Scheduled Tasks и permanent WMI subscriptions;
- расширенный security status: Defender, exclusions, Firewall, UAC, SmartScreen, proxy и hosts;
- Windows Restart Manager для определения реальных владельцев блокировки файла;
- безопасная остановка только процесса, чей executable path точно совпадает с проверенной целью;
- защищённый карантин с SHA-256 и восстановлением;
- удаление занятого файла при следующей загрузке через `MoveFileEx`;
- журнал pending remediation и проверка результата после перезагрузки;
- JSON-режимы для автоматизации.

## Установка

Скачайте `VoidGuard-v0.2.0-Portable.zip` из **Releases**, распакуйте и запустите:

```cmd
VoidGuard.cmd
```

Ручной запуск:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\VoidGuard.ps1
```

Для просмотра достаточно обычных прав. Остановка процесса и удаление при загрузке требуют запуска CMD/PowerShell от администратора.

## Безопасность remediation

VoidGuard не предоставляет `--force-delete-anything` и не принимает произвольную команду «убить PID».

Операция блокируется для:

- Windows и Program Files;
- Windows Resource Protection;
- файлов с действительной подписью Microsoft;
- TrustedInstaller-owned объектов;
- корней томов, каталогов и reparse points;
- критических процессов Windows;
- процесса, executable path которого не совпадает с выбранным файлом.

Для DLL или файла, удерживаемого сторонним процессом, VoidGuard не завершает владельца автоматически. Безопасный путь — назначить удаление на следующую загрузку и затем проверить ledger.

## CLI

```powershell
# Сканирование
.\VoidGuard.ps1 -Mode QuickScan -Professional
.\VoidGuard.ps1 -Mode CustomScan -Path "C:\Downloads" -Json

# Состояние и анализ
.\VoidGuard.ps1 -Mode Status -Json
.\VoidGuard.ps1 -Mode Processes -Json
.\VoidGuard.ps1 -Mode Persistence -Json
.\VoidGuard.ps1 -Mode Locks -Path "C:\Suspicious\payload.exe" -Json

# Подтверждённая остановка точного процесса + карантин
.\VoidGuard.ps1 -Mode Remediate -Path "C:\Suspicious\payload.exe" `
  -StopTargetProcess -TargetProcessId 4242 -Confirmed -Json

# Если файл остаётся заблокирован — удалить при следующей загрузке
.\VoidGuard.ps1 -Mode Remediate -Path "C:\Suspicious\payload.exe" `
  -ScheduleOnReboot -Confirmed -Json

# После перезагрузки проверить результат
.\VoidGuard.ps1 -Mode Pending -Json
```

Подробности: [docs/USAGE.md](docs/USAGE.md), [docs/REMEDIATION.md](docs/REMEDIATION.md) и [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Важное предупреждение

VoidGuard — дополнительный диагностический инструмент, а не замена Microsoft Defender или коммерческому EDR. Эвристические результаты могут содержать ложные срабатывания. Проверяйте путь, подпись, хеш и причины оценки перед remediation.

## Roadmap

- **v0.3** — HTML/JSON reports, экспорт incident bundle и улучшенный PE-анализ;
- **v0.4** — YARA и подписываемые rule packs;
- **v0.5** — интеграция Microsoft Defender Offline;
- **v1.0** — стабильный CLI contract и подписанные релизы.

## Лицензия

MIT. Используйте только для законной защиты и анализа собственных систем.
