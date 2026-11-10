# Changelog

Все заметные изменения VoidGuard документируются здесь.

## [0.4.0] — 2026-11-10

### Добавлено
- Снимки состояния Windows (System Baseline): Defender, Firewall, UAC, SmartScreen, прокси, службы, задания, автозапуск, hosts и SHA-256 выбранных файлов.
- Команды `BaselineCreate`, `BaselineDiff` и `DefenderOffline` в CLI и TUI.
- Локальный JSON schema v1 без перезаписи существующего baseline, проверка целостности структуры и сравнение по именованным разделам.
- Результаты ADDED/REMOVED/CHANGED; ошибки сбора помечаются PARTIAL без ложного вывода об удалении.
- Defender Offline: readiness, проверка ОС/прав/WinRE/BitLocker/Defender и двойное подтверждение запуска.
- Тесты на Windows PowerShell 5.1 и PowerShell 7, включая безопасную проверку CLI.

### Ограничения
- Baseline не подписан: доверенную копию надо хранить вне проверяемой системы.
- Изменения настроек сами по себе не доказывают заражение.
- Defender Offline может немедленно перезагрузить компьютер; реальный запуск не выполняется в CI.


## [0.3.4] — 2026-11-10

### Исправлено

- удалены runtime-подмены функций Scanner и главного цикла UI; исправления совместимости перенесены в исходные модули;
- исправлена обработка пустых и одноэлементных результатов при сканировании в PowerShell 5.1;
- добавлены счётчики `FilesDiscovered`, `FilesScanned`, `FilesSkipped`, `FilesFailed`, а также диагностика файлов и ошибок перечисления;
- неполная проверка помечается `PARTIAL`, если были ошибки, достигнут лимит или не было успешно обработанных файлов;
- при восстановлении из карантина проверяются размер и SHA-256, ID и схема метаданных, целевой путь и конфликты файлов;
- блокируются reparse points в файловых и родительских каталогах, участвующих в защитных операциях;
- Pending Ledger не утверждает успешное удаление до подтверждённой перезагрузки Windows;
- при `WhatIf` операция delete-on-reboot не регистрируется;
- доверие к встроенным rule packs закреплено в коде по каталогу, метаданным, составу файлов и SHA-256, а не только по содержимому manifest;
- проверка rule packs отклоняет пути через reparse points и изменённый manifest.

### Добавлено

- статусы `COMPLETE` / `PARTIAL` и отчёт о причинах неполной проверки;
- статусы `AWAITING_REBOOT`, `VERIFICATION_UNAVAILABLE`, `VERIFICATION_INCOMPLETE` и `LEDGER_READ_ERROR` для Pending Ledger;
- отдельные тесты сканирования, целостности карантина, проверки загрузки Windows и доверия к правилам;
- единые сведения о версии в документации.

### Ограничения

- `PARTIAL` не означает, что на компьютере нет угроз;
- локальная проверка SHA-256 и reparse-путей не заменяет проверку подлинности релизного архива;
- VoidGuard остаётся вспомогательной защитной утилитой и не заменяет Microsoft Defender.


## [0.3.3] — 2026-08-02

### Исправлено

- устранена ошибка `Argument types do not match` в `PERSISTENCE MATRIX` при работе через Windows PowerShell 5.1;
- исправлено разворачивание одноэлементного результата Custom Scan, из-за которого у объекта отсутствовало свойство `Count`;
- исправлен вывод пустых результатов `Processes`, `Pending` и `Locks`: JSON-режим теперь возвращает корректный массив `[]`;
- добавлены совместимые реализации Quick Scan и Custom Scan с явным сохранением массивов и преобразованием `Generic.List` через `ToArray()`;
- восстановлена отсутствовавшая команда `Show-VGLoadingBar`, используемая интерактивным Quick Scan;
- расширена диагностика CLI-ошибок: JSON содержит тип исключения, позицию и стек вызовов;
- ошибка отдельной операции интерактивного меню больше не завершает весь VoidGuard;
- ошибка проверки pending ledger при запуске больше не блокирует открытие главного меню.

### Добавлено

- новый модуль `VoidGuard.Stability.psm1` с исправлениями совместимости Windows PowerShell 5.1;
- пункт интерактивного меню `SYSTEM SELF-TEST`;
- CLI-режим `SelfTest` для проверки загрузки обязательных команд;
- полный регрессионный прогон всех безопасных режимов в отдельном процессе `powershell.exe`;
- проверка создания автономных JSON и HTML reports;
- отдельные stability-тесты для PowerShell 7 и Windows PowerShell 5.1.

### Проверено

- `SelfTest`, `Status`, `Processes`, `Persistence`, `Pending`, `RulePacks`;
- `QuickScan`, `CustomScan`, `Locks`, `Yara`;
- безопасный dry-run remediation без подтверждения;
- генерация JSON/HTML-отчётов и визуальная демонстрация;
- совместимость исходников и релизных архивов с Windows PowerShell 5.1.

## [0.3.2] — 2026-08-02

### Исправлено

- устранено падение интерактивного меню с ошибкой форматирования строки сразу после стартовой анимации;
- аргументы номера, маркера и подписи пункта передаются оператору `-f` единым массивом;
- добавлена явная проверка пустого списка пунктов меню;
- череп на стартовом экране центрируется относительно полной ширины надписи VOIDGUARD;
- центрирование рассчитывается по видимым границам рисунка с учётом Braille Blank `U+2800`;
- общие пустые поля рисунка удаляются без изменения внутренних отступов и формы черепа.

### Проверено

- добавлены регрессионные тесты меню и консольной компоновки;
- тесты запускаются в PowerShell 7 и Windows PowerShell 5.1;
- CI подтверждает установку исправленной функции внутри области модуля `VoidGuard.UI`.

## [0.3.1] — 2026-08-02

### Исправлено

- устранён parser failure `Unexpected token` в `VoidGuard.Animation.psm1` при запуске через Windows PowerShell 5.1;
- все отслеживаемые PowerShell-файлы нормализованы в UTF-8 с BOM;
- Portable и Source ZIP повторно нормализуют `.ps1`, `.psm1` и `.psd1` перед упаковкой;
- Source ZIP собирается единым release builder из отслеживаемых файлов;
- CI проверяет BOM и реальный запуск репозитория, Portable ZIP и Source ZIP через `powershell.exe` 5.1;
- PowerShell 7 smoke test сохранён как отдельный этап.

### Причина

- PowerShell 7 распознаёт UTF-8 без BOM, но Windows PowerShell 5.1 использует системную ANSI-кодировку;
- Unicode tree-символы, кириллица и логотип повреждались до синтаксического разбора.

## [0.3.0] — 2026-08-02

### Добавлено

- manifest-based rule packs с проверкой schema, безопасных путей и SHA-256;
- режимы доверия `bundled`, `signed` и запрещённый по умолчанию `local`;
- RSA-SHA256 verification для внешних packs через `Rules/trusted-publishers.json`;
- встроенный `voidguard.core` с defensive regex и YARA rules;
- опциональный YARA CLI discovery, timeout и ограничение размера файла;
- PE parser: architecture, sections, compile timestamp и optional-header metadata;
- entropy sampling и обнаружение PE-содержимого с неправильным расширением;
- offline HTML и JSON reports с HTML encoding входных данных;
- CLI-режимы `RulePacks`, `Yara`, `-ReportPath` и `-ReportFormat`;
- документация rule-pack format, trust model и reports;
- smoke-тесты integrity pack, pattern match, PE parser и report escaping.

### Изменено

- Quick/Custom Scan объединяет metadata, Authenticode, PE, entropy, rule-pack и YARA evidence;
- лимит scan увеличен до 4000 файлов;
- scan result включает inventory rule packs и статус YARA;
- `.gitattributes` фиксирует LF для rule-pack файлов, чтобы manifest SHA-256 совпадал на Windows и Unix;
- release documentation обновлена для `SIGNATURE GRID`.

### Безопасность

- невалидные или недоверенные packs видны в inventory, но не загружаются;
- YARA и pattern rules не получают полномочий quarantine/remediation;
- YARA binary не загружается VoidGuard автоматически;
- HTML reports не содержат JavaScript или сетевых ресурсов.

## [0.2.0] — 2026-08-02

### Добавлено

- Windows Restart Manager для определения реальных владельцев файловой блокировки;
- безопасная остановка только точного процесса-цели после повторной policy-проверки;
- scheduled deletion при следующей загрузке через `MoveFileEx`;
- pending remediation ledger с SHA-256 и post-reboot verification;
- `PERSISTENCE MATRIX` для Run/RunOnce, Startup folders, Services, Scheduled Tasks и WMI subscriptions;
- оценка риска persistence-команд и связанных файлов;
- command line, parent PID и TCP connections в process analyzer;
- exclusions Defender, Behavior Monitor, IOAV, SmartScreen, user proxy и hosts metadata в security status;
- интерактивный экран locked-file remediation;
- CLI-режимы `Processes`, `Persistence`, `Locks`, `Remediate` и `Pending`;
- расширенные smoke-тесты защитных инвариантов.

### Изменено

- карантин использует Restart Manager вместо проверки только пути executable;
- лимит Quick/Custom Scan увеличен до 3500 файлов;
- TUI и документация обновлены для remediation workflow.

### Безопасность

- отсутствует универсальный `force delete`;
- запрещено завершение критических процессов и процессов с несовпадающим executable path;
- системные policy-блокировки нельзя обойти CLI-параметром.

## [0.1.0] — 2026-08-02

### Добавлено

- интерактивная TUI-консоль с управлением стрелками;
- cinematic-загрузка, glitch-эффекты, fake-code и tree-анимации с меткой `[VISUAL]`;
- три пользовательских Unicode-черепа;
- быстрый и выборочный эвристический скан файлов;
- SHA-256, проверка Authenticode и обнаружение двойных расширений;
- анализ опасных скриптовых шаблонов;
- инспектор процессов и автозапуска;
- проверка Microsoft Defender, Firewall и UAC;
- защищённый карантин с метаданными и восстановлением;
- блокировка Windows, Program Files, WRP, Microsoft-signed, TrustedInstaller и reparse-point целей;
- CLI-режимы для автоматизации и JSON-вывода;
- CI-проверка PowerShell-синтаксиса и автоматический GitHub Release.

### Ограничения

- v0.1.0 не является полноценной заменой антивирусу;
- утилита не завершает процессы принудительно;
- драйверы ядра, rootkit и PPL-цели не удаляются;
- база известных вредоносных хешей поставляется пустой и предназначена для локального пополнения.
