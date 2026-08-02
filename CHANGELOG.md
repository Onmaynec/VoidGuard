# Changelog

Все заметные изменения VoidGuard документируются здесь.

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
