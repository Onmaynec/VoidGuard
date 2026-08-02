# Архитектура

```text
VoidGuard.ps1
 ├── VoidGuard.Animation  — визуальные эффекты
 ├── VoidGuard.Protection — системная политика безопасности
 ├── VoidGuard.Scanner    — файловая эвристика и SHA-256
 ├── VoidGuard.System     — Defender, Firewall, процессы, автозапуск
 ├── VoidGuard.Quarantine — безопасное перемещение и восстановление
 └── VoidGuard.UI         — TUI и управление клавиатурой
```

## Trust boundary

Интерфейс не принимает окончательное решение о допустимости карантина. `VoidGuard.Quarantine` повторно вызывает `Test-VoidGuardProtectedTarget` перед перемещением файла.

## Реальные и декоративные события

Все декоративные строки имеют префикс `[VISUAL]`. Они не попадают в детектирующие решения и не означают, что операция выполнена.

## План развития

- v0.2: отчёты, Scheduled Tasks, Services, расширенный анализ PE;
- v0.3: подписываемые rule packs и YARA integration;
- v0.4: безопасный remediation plan и удаление после перезагрузки;
- v1.0: стабильный CLI contract, обновления правил и signed release pipeline.
