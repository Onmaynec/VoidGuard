<div align="center">

# VOIDGUARD

**CYBERPUNK WINDOWS THREAT ANALYSIS & REMEDIATION CONSOLE**  
PowerShell 5.1+ · Windows 10/11 · defensive security toolkit

[![CI](https://github.com/Onmaynec/VoidGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Onmaynec/VoidGuard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Onmaynec/VoidGuard?display_name=tag)](https://github.com/Onmaynec/VoidGuard/releases)
[![License](https://img.shields.io/badge/license-MIT-00ff77)](LICENSE)

`[ SCAN ]  [ CORRELATE ]  [ CONTAIN ]  [ VERIFY ]  [ REPORT ]`

</div>

## Что это

**VoidGuard** — консольная Windows-утилита для проверки подозрительных файлов, процессов, механизмов закрепления и состояния встроенной защиты.

Декоративные эффекты всегда помечаются `[VISUAL]` и не участвуют в решении об угрозе. Реальный скоринг строится из проверяемых признаков: пути, подписи, SHA-256, PE-метаданных, энтропии, persistence, rule packs и опционального YARA.

## Возможности v0.3.3 — МАКСИМАЛЬНАЯ СТАБИЛЬНОСТЬ

- полноэкранное TUI-меню с управлением стрелками и cinematic-эффектами;
- исправленное форматирование пунктов меню в Windows PowerShell 5.1;
- автоматическое центрирование стартового черепа относительно логотипа VOIDGUARD;
- защищённый цикл меню: ошибка отдельной операции больше не закрывает всю программу;
- встроенный пункт `SYSTEM SELF-TEST` и CLI-режим `SelfTest` для проверки обязательных компонентов;
- совместимые обёртки Quick Scan и Custom Scan без ошибок одноэлементных массивов и `Generic.List` в PowerShell 5.1;
- корректный JSON `[]` для пустых результатов Processes, Pending и Locks;
- Quick Scan и сканирование выбранного файла/каталога;
- SHA-256, Authenticode, двойные расширения и скриптовые эвристики;
- PE parser: архитектура, секции, compile timestamp и несоответствие расширения содержимому;
- entropy sampling для обнаружения упакованного или зашифрованного содержимого;
- доверенные rule packs с schema validation и SHA-256 каждого файла;
- RSA-SHA256 verification для внешних packs из локального trust store;
- встроенный defensive core pack с LOLBin/persistence patterns;
- опциональная интеграция с установленным пользователем `yara.exe` / `yara64.exe`;
- офлайн HTML и JSON reports без JavaScript, аналитики и внешних ресурсов;
- Process Analyzer, `PERSISTENCE MATRIX` и расширенный Windows security status;
- Windows Restart Manager, защищённый карантин и delete-on-reboot ledger;
- проверенная совместимость с Windows PowerShell 5.1 и PowerShell 7;
- JSON CLI для автоматизации.

## Установка

Скачайте `VoidGuard-v0.3.3-Portable.zip` из **Releases**, распакуйте в новую папку и запустите:

```cmd
VoidGuard.cmd
```

Ручной запуск:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\VoidGuard.ps1
```

Проверка загрузки всех обязательных компонентов:

```powershell
.\VoidGuard.ps1 -Mode SelfTest -Professional -NoAnimation -Json
```

> Не смешивайте файлы разных версий. Полностью удалите старую распакованную папку и распакуйте `v0.3.3` в новую.

YARA не входит в архив и не скачивается автоматически. Без него VoidGuard продолжает использовать встроенные правила, PE-анализ и эвристику.

## Rule-pack trust model

Pack активируется только после проверки:

1. `manifest.json` и поддерживаемой schema;
2. отсутствия absolute path / `..` / выхода из каталога pack;
3. SHA-256 каждого перечисленного файла;
4. режима доверия:
   - `bundled` — pack поставлен внутри проверенного релиза VoidGuard;
   - `signed` — RSA-SHA256 подпись проверена ключом из `Rules/trusted-publishers.json`;
   - `local` — запрещён по умолчанию и требует явной настройки.

Невалидный pack показывается в inventory, но не участвует в сканировании.

## CLI

```powershell
# Самопроверка среды
.\VoidGuard.ps1 -Mode SelfTest -Professional -NoAnimation -Json

# Сканирование с автоматическим rule engine
.\VoidGuard.ps1 -Mode QuickScan -Professional
.\VoidGuard.ps1 -Mode CustomScan -Path "C:\Downloads" -Json

# Сканирование + офлайн HTML/JSON reports
.\VoidGuard.ps1 -Mode CustomScan -Path "C:\Downloads" `
  -ReportPath ".\Reports\downloads-scan" -ReportFormat Both

# Состояние packs и YARA
.\VoidGuard.ps1 -Mode RulePacks -Json
.\VoidGuard.ps1 -Mode Yara -Path "C:\Suspicious\payload.exe" -Json

# Состояние системы, процессы и persistence
.\VoidGuard.ps1 -Mode Status -Json
.\VoidGuard.ps1 -Mode Processes -Json
.\VoidGuard.ps1 -Mode Persistence -Json
.\VoidGuard.ps1 -Mode Locks -Path "C:\Suspicious\payload.exe" -Json

# Безопасная remediation
.\VoidGuard.ps1 -Mode Remediate -Path "C:\Suspicious\payload.exe" `
  -StopTargetProcess -TargetProcessId 4242 -Confirmed -Json
.\VoidGuard.ps1 -Mode Remediate -Path "C:\Suspicious\payload.exe" `
  -ScheduleOnReboot -Confirmed -Json
.\VoidGuard.ps1 -Mode Pending -Json
```

Подробности:

- [Использование](docs/USAGE.md)
- [Rule packs и YARA](docs/RULE_PACKS.md)
- [Reports](docs/REPORTS.md)
- [Safe remediation](docs/REMEDIATION.md)
- [Архитектура](docs/ARCHITECTURE.md)

## Проверки стабильности

CI запускает отдельные проверки в PowerShell 7 и Windows PowerShell 5.1. Полный прогон реально запускает `SelfTest`, `Status`, `Processes`, `Persistence`, `Pending`, `RulePacks`, `QuickScan`, `CustomScan`, `Locks`, `Yara`, безопасный dry-run remediation, генерацию HTML/JSON-отчётов и визуальную демонстрацию.

## Безопасность remediation

VoidGuard не предоставляет `--force-delete-anything` и не принимает произвольную команду «убить PID». Windows/Program Files, WRP, Microsoft-signed, TrustedInstaller, root, directory, reparse-point и критические процессные цели блокируются backend-политикой непосредственно перед действием.

## Важное предупреждение

VoidGuard — дополнительный диагностический инструмент, а не замена Microsoft Defender или коммерческому EDR. Эвристические, pattern и YARA результаты могут содержать ложные срабатывания. Проверяйте путь, подпись, хеш и все причины оценки перед remediation.

## Roadmap

- **v0.4** — Defender Offline orchestration и baseline/diff состояния системы;
- **v0.5** — безопасное обновление rule packs и incident bundle;
- **v1.0** — стабильный CLI contract и подписанные приложения/релизы.

## Лицензия

MIT. Используйте только для законной защиты и анализа собственных систем.
