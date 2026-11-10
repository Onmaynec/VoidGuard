# Архитектура VoidGuard v0.4.0

```text
VoidGuard.ps1
 ├── VoidGuard.Animation    — визуальные эффекты
 ├── VoidGuard.Protection   — canonical path и системная policy
 ├── VoidGuard.RulePacks    — manifest, SHA-256, RSA trust и optional YARA
 ├── VoidGuard.Scanner      — metadata, Authenticode, PE, entropy и scoring
 ├── VoidGuard.System       — Defender, Firewall, процессы, сеть, автозапуск
 ├── VoidGuard.Persistence  — Services, Scheduled Tasks, WMI, Run keys
 ├── VoidGuard.Remediation  — Restart Manager, process stop, delete-on-reboot
 ├── VoidGuard.Quarantine   — безопасное перемещение и восстановление
 ├── VoidGuard.IntegritySnapshot — снимки наблюдаемого состояния
 ├── VoidGuard.IntegrityBaseline — сохранение и сравнение JSON baseline
 ├── VoidGuard.DefenderOffline — проверка готовности и запуск по согласию
 ├── VoidGuard.Reporting    — offline HTML/JSON serialization
 ├── VoidGuard.UI           — TUI и управление клавиатурой
 ├── VoidGuard.ConsoleFix   — центрирование и форматирование вывода
 └── VoidGuard.Stability    — диагностика и самопроверка без runtime-подмен
```

## Главный trust boundary

TUI, rule packs, YARA и reports не обладают правом самостоятельно удалить файл или завершить процесс. Перед каждым изменяющим действием remediation/quarantine backend повторно выполняет policy-проверки.

```text
Untrusted file / process / persistence entry
                 ↓
Metadata + signature + hash + PE + entropy
                 ↓
Trusted pattern packs + optional YARA
                 ↓
Explainable risk result
                 ↓
          user review
                 ↓
Canonical path / WRP / owner / signature / reparse checks
                 ↓
Exact-process validation or delete-on-reboot
                 ↓
Quarantine / pending ledger / post-reboot verification
```

## Неполные результаты сканирования

Scanner учитывает кандидатов, успешно обработанные и пропущенные файлы, ошибки обработки и ошибки перечисления. При ошибках, отсутствии проверенных объектов или достижении установленного лимита `Complete` становится `false`, а `ScanStatus` — `PARTIAL`. Нулевое число находок при таком статусе не доказывает отсутствие угроз.

## Rule engine

`VoidGuard.RulePacks` перечисляет каталоги в `Rules\Packs` и проверяет:

- schema manifest;
- id/version/trust mode;
- отсутствие absolute path, `..` и выхода из pack root;
- разрешённые расширения файлов правил;
- SHA-256 каждого файла;
- RSA-SHA256 detached signature для режима `signed`;
- явное включение pack в конфигурации.

Только packs с `Enabled`, `IntegrityValid` и `Trusted` участвуют в сканировании.

### Trust modes

- `bundled` — pack внутри `Rules\Packs` официального release archive;
- `signed` — manifest payload проверен ключом из `Rules\trusted-publishers.json`;
- `local` — запрещён по умолчанию, разрешается только явной настройкой.

## Scanner pipeline

Для каждого кандидата scanner может использовать:

1. путь, атрибуты и расширение;
2. SHA-256 и known-bad table;
3. Authenticode;
4. PE signature, machine, sections и compile timestamp;
5. sample entropy;
6. встроенные script patterns;
7. regex rules из доверенных packs;
8. YARA rules из доверенных packs, если CLI доступен.

Каждый сигнал добавляет отдельную строку в `Reasons`. YARA не заменяет policy и не инициирует remediation.

## Reporting

`VoidGuard.Reporting` получает уже сформированный объект результата. Модуль:

- не вызывает scan/remediation самостоятельно;
- создаёт JSON schema envelope;
- HTML-экранирует пути, причины и другие данные;
- не вставляет JavaScript, внешние стили, шрифты или analytics;
- может работать в полностью отключённой от сети среде.

## Карантин и Pending Ledger

Восстановление из карантина заново проверяет SHA-256, размер, ID, metadata schema и конечный путь, включая родительские reparse points. Pending Ledger связывает проверку удаления с фактом перезагрузки Windows. Отсутствие файла до новой загрузки не означает выполнение операции `MoveFileEx`.

## Остановка процесса

`Stop-VoidGuardTargetProcess` разрешает действие только если:

- PID не относится к встроенному списку критических процессов;
- executable path доступен;
- executable path точно совпадает с canonical path цели;
- файл процесса проходит `Test-VoidGuardProtectedTarget`;
- пользователь передал явное подтверждение.

## Delete-on-reboot

`Register-VoidGuardDeleteOnReboot` использует Windows API `MoveFileEx` с `MOVEFILE_DELAY_UNTIL_REBOOT`. До регистрации сохраняются canonical path и SHA-256. После загрузки ledger различает удалённый, оставшийся и заменённый другим хешем объект.

## Реальные и декоративные события

Все декоративные строки имеют префикс `[VISUAL]`. Они не попадают в детектирующие решения и не означают, что операция выполнена.

## План развития

- v0.4.0: Defender Offline preflight и baseline/diff реализованы;
- v0.5: безопасное обновление packs и incident bundle;
- v1.0: стабильный CLI contract и подписанные приложения/релизы.


## System Integrity v0.4.0

Снимки содержат разделы Security, Services, Tasks, Startup и Files, со статусами COMPLETE/PARTIAL и явными ошибками. Неполный раздел при сравнении пропускается целиком: отсутствие доступной записи не означает её удаление. JSON проверяется по схеме v1, уникальности ключей и идентичности компьютера.

Defender Offline отделён от диагностики. Предпросмотр не выполняет изменяющих действий. Реальная команда Start-MpWDOScan разрешена только после двойного подтверждения и повторной проверки готовности. Возвращаемый REQUESTED не означает завершённое антивирусное сканирование.
