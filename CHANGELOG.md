# Changelog

Все заметные изменения VoidGuard документируются здесь.

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
