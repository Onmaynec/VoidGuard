# Использование VoidGuard v0.5.0

## Интерактивный режим

```cmd
VoidGuard.cmd
```

Управление:

- `↑` / `↓` — выбор пункта;
- `Enter` — открыть;
- `Esc` — назад;
- `F1` — справка.

Quick Scan и Custom Scan автоматически используют активные rule packs. YARA подключается автоматически, только когда пользователь установил `yara.exe` или указал путь в `Config/settings.json`.

## Командные режимы

```powershell
# Быстрое сканирование
.\VoidGuard.ps1 -Mode QuickScan -Professional

# Сканирование файла или папки
.\VoidGuard.ps1 -Mode CustomScan -Path "C:\Users\User\Downloads"

# Scan + HTML и JSON отчёты
.\VoidGuard.ps1 -Mode CustomScan `
  -Path "C:\Users\User\Downloads" `
  -ReportPath ".\Reports\downloads" `
  -ReportFormat Both

# Inventory rule packs
.\VoidGuard.ps1 -Mode RulePacks -Json

# Ручной YARA scan одного файла
.\VoidGuard.ps1 -Mode Yara -Path "C:\Suspicious\payload.exe" -Json

# Состояние Windows security components
.\VoidGuard.ps1 -Mode Status -Json

# Анализ процессов
.\VoidGuard.ps1 -Mode Processes -Json

# Анализ persistence
.\VoidGuard.ps1 -Mode Persistence -Json

# Кто удерживает файл
.\VoidGuard.ps1 -Mode Locks -Path "C:\Suspicious\payload.exe" -Json

# Остановить точный процесс и попробовать карантин
.\VoidGuard.ps1 -Mode Remediate `
  -Path "C:\Suspicious\payload.exe" `
  -StopTargetProcess `
  -TargetProcessId 4242 `
  -Confirmed `
  -Json

# Если файл остаётся занятым — назначить удаление при загрузке
.\VoidGuard.ps1 -Mode Remediate `
  -Path "C:\Suspicious\payload.exe" `
  -ScheduleOnReboot `
  -Confirmed `
  -Json

# Проверить результат после перезагрузки
.\VoidGuard.ps1 -Mode Pending -Json

# Демонстрация визуальных эффектов без изменений системы
.\VoidGuard.ps1 -Mode Demo
```

## System Integrity

```powershell
# Сохранить стандартный снимок Windows
.\VoidGuard.ps1 -Mode BaselineCreate -Json

# Сохранить выбранный файл, без hosts
.\VoidGuard.ps1 -Mode BaselineCreate -BaselinePath "C:\Temp\baseline.json" -IntegrityPaths "C:\Temp\sample.exe" -IntegritySections Files -NoHosts -Json

# Сравнить с исходным состоянием
.\VoidGuard.ps1 -Mode BaselineDiff -BaselinePath "C:\Temp\baseline.json" -Json

# Проверить готовность Defender Offline (без перезагрузки)
.\VoidGuard.ps1 -Mode DefenderOffline -Json

# После сохранения документов и подготовки BitLocker
.\VoidGuard.ps1 -Mode DefenderOffline -Confirmed -RebootAcknowledged
```

По умолчанию baseline сохраняется в %LOCALAPPDATA%\VoidGuard\Baselines. При PARTIAL часть данных недоступна. Подробности — [System Integrity](SYSTEM_INTEGRITY.md).

## Threat Intelligence v0.5.0

```powershell
# Проверка локальной подписанной папки — никаких изменений
.\VoidGuard.ps1 -Mode RuleUpdate -UpdateSource "C:\Updates\example.rules" -Json

# Установка после проверки — старая версия уходит в историю
.\VoidGuard.ps1 -Mode RuleUpdate -UpdateSource "C:\Updates\example.rules" -Confirmed -Json

# Список сохранённых версий, безопасный откат
.\VoidGuard.ps1 -Mode RuleHistory -RulePackId "example.rules" -Json
.\VoidGuard.ps1 -Mode RuleRollback -RulePackId "example.rules" -HistoryId "h-20261110120000-abc123def456" -Confirmed -Json

# Явное включение и отключение нового пакета в движке
.\VoidGuard.ps1 -Mode RuleActivate -RulePackId "example.rules" -Enable -Confirmed -Json
.\VoidGuard.ps1 -Mode RuleActivate -RulePackId "example.rules" -Disable -Confirmed -Json

# Предпросмотр Incident Bundle без записи
.\VoidGuard.ps1 -Mode IncidentPreview -IncidentPath "C:\Temp\incident.zip" -Json

# Сохранение локального ZIP со стандартным ограниченным набором полей
.\VoidGuard.ps1 -Mode IncidentExport -IncidentPath "C:\Temp\incident.zip" -Confirmed -Json

# При необходимости — включить скан выбранного пути и метаданные событий
.\VoidGuard.ps1 -Mode IncidentExport -IncidentPath "C:\Temp\incident-detail.zip" -IncidentScanPath "C:\Temp\sample.ps1" -IncludeEventLogs -Confirmed -Json

# Расширенный экспорт с персональными полями; используйте только при необходимости
.\VoidGuard.ps1 -Mode IncidentExport -IncidentPath "C:\Temp\incident-full.zip" -IncludeSensitive -Confirmed -Json
```

Запрещён автоматический импорт неподписанных пакетов. Публичные ключи издателей добавляются вручную в `Rules/trusted-publishers.json` после независимой проверки. Если ключ отсутствует, установка заблокирована. Новые пакеты не активируются без отдельной команды.

Incident ZIP создаётся локально, без сетевых запросов. Перед отправкой кому-либо проверьте архив самостоятельно. [Подробное описание](THREAT_INTELLIGENCE.md).

## Форматы отчётов

`-ReportPath` доступен для любого режима, который возвращает объект анализа. Расширение можно не указывать:

```powershell
.\VoidGuard.ps1 -Mode QuickScan `
  -ReportPath ".\Reports\quick-2026-08-02" `
  -ReportFormat Both
```

Будут созданы:

```text
Reports\quick-2026-08-02.json
Reports\quick-2026-08-02.html
```

HTML полностью автономен и не содержит JavaScript или сетевых ресурсов.

## Поля файловой находки v0.3

Кроме пути, SHA-256 и Authenticode результат может содержать:

- `IsPE`;
- `PEArchitecture`;
- `PESections`;
- `PECompileTimeUtc`;
- `Entropy`;
- `RuleMatches`;
- `YaraMatches`;
- список объяснимых `Reasons`.

## Remediation workflow

1. Выполните scan и изучите все причины оценки.
2. Проверьте цифровую подпись, SHA-256, PE и rule matches.
3. Используйте `Locks`, чтобы определить владельцев блокировки.
4. Остановка процесса разрешена только для executable, который точно совпадает с выбранным файлом.
5. Попробуйте карантин.
6. Если файл нельзя переместить, назначьте удаление при следующей загрузке.
7. Перезагрузите Windows и выполните `Pending`.

## Полнота сканирования

Начиная с v0.3.4 JSON содержит:

- `FilesDiscovered` — кандидаты сканирования;
- `FilesScanned` — успешно обработанные файлы;
- `FilesSkipped` — объекты без результата анализа;
- `FilesFailed` — ошибки обработки;
- `FileErrors` и `EnumerationErrors` — диагностика;
- `ScanLimitReached` — достигнут настроенный лимит кандидатов;
- `ScanStatus` и `Complete` — `COMPLETE`/`true` либо `PARTIAL`/`false`.

При `PARTIAL` нельзя заключать, что угроз нет, даже если `Findings` пуст. Для более полного прохода увеличьте `maxFilesPerScan` или проверяйте каталоги раздельно.

## Pending Ledger

`AWAITING_REBOOT` означает отсутствие подтверждённой перезагрузки после назначения операции. `REMOVED_VERIFIED` означает, что файл отсутствует после новой загрузки. `STILL_PRESENT` и `REPLACED_OR_RECREATED` показывают сохранившийся либо изменённый объект. `VERIFICATION_UNAVAILABLE` и `VERIFICATION_INCOMPLETE` означают, что проверку нельзя завершить. `LEDGER_READ_ERROR` сообщает о проблеме чтения или записи данных.

## Интерпретация риска

- `LOW` — слабые эвристические признаки;
- `MEDIUM` — объект требует ручной проверки;
- `HIGH` — несколько серьёзных признаков;
- `CRITICAL` — известный вредоносный хеш, YARA evidence или сильная комбинация признаков.

Pattern/YARA match не является разрешением на автоматическое удаление. Всегда проверяйте контекст.
