# Архитектура VoidGuard v0.2.0

```text
VoidGuard.ps1
 ├── VoidGuard.Animation    — визуальные эффекты
 ├── VoidGuard.Protection   — canonical path и системная policy
 ├── VoidGuard.Scanner      — файловая эвристика, SHA-256, Authenticode
 ├── VoidGuard.System       — Defender, Firewall, процессы, сеть, автозапуск
 ├── VoidGuard.Persistence  — Services, Scheduled Tasks, WMI, Run keys
 ├── VoidGuard.Remediation  — Restart Manager, process stop, delete-on-reboot
 ├── VoidGuard.Quarantine   — безопасное перемещение и восстановление
 └── VoidGuard.UI           — TUI и управление клавиатурой
```

## Trust boundary

TUI не обладает правом самостоятельно удалить файл или завершить процесс. Перед каждым действием низкоуровневый модуль повторно вызывает policy-проверки.

```text
User selection
      ↓
Canonical path resolution
      ↓
System / WRP / signature / owner / reparse checks
      ↓
Restart Manager lock inventory
      ↓
Exact-process validation or delete-on-reboot
      ↓
Quarantine / pending ledger
      ↓
Post-reboot verification
```

## Остановка процесса

`Stop-VoidGuardTargetProcess` разрешает действие только если:

- PID не относится к встроенному списку критических процессов;
- executable path доступен;
- executable path точно совпадает с canonical path цели;
- файл процесса проходит `Test-VoidGuardProtectedTarget`;
- пользователь передал явное подтверждение.

Это специально исключает универсальный интерфейс `kill arbitrary PID`.

## Delete-on-reboot

`Register-VoidGuardDeleteOnReboot` использует документированный Windows API `MoveFileEx` с `MOVEFILE_DELAY_UNTIL_REBOOT`. До регистрации сохраняются canonical path и SHA-256. После загрузки `Get-VoidGuardPendingRemediations -Verify` проверяет, остался ли объект.

## Persistence Matrix

Persistence engine объединяет:

- Registry Run / RunOnce / Policies Explorer Run;
- пользовательскую и общую Startup folder;
- Win32 services;
- Scheduled Tasks actions;
- permanent WMI event consumers and bindings.

Каждая запись получает объяснимый risk score на основе команды, расположения и анализа связанного файла.

## Реальные и декоративные события

Все декоративные строки имеют префикс `[VISUAL]`. Они не попадают в детектирующие решения и не означают, что операция выполнена.

## План развития

- v0.3: HTML/JSON incident reports, экспорт bundle, расширенный PE-анализ;
- v0.4: YARA и подписываемые rule packs;
- v0.5: Defender Offline orchestration;
- v1.0: стабильный CLI contract и signed release pipeline.
