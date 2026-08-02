# VOIDGUARD v0.2.0 — LOCKDOWN PROTOCOL

Вторая публичная версия превращает VoidGuard из базового инспектора в безопасную консоль анализа закрепления и remediation занятых файлов.

## Главное

- Windows Restart Manager определяет процессы и службы, реально удерживающие файл;
- точный вредоносный executable можно остановить только после повторной проверки политики и ручного подтверждения;
- заблокированный файл можно назначить на удаление при следующей загрузке Windows;
- pending remediation ledger сохраняет путь, SHA-256 и проверяет результат после перезагрузки;
- новая `PERSISTENCE MATRIX` анализирует Run/RunOnce, Startup folders, Services, Scheduled Tasks и WMI subscriptions;
- процесс-анализатор показывает command line, parent PID и установленные TCP-соединения;
- security status теперь показывает exclusions Defender, SmartScreen, proxy и время изменения hosts;
- обновлено TUI-меню и добавлены новые JSON CLI-режимы.

## Защитные ограничения

VoidGuard по-прежнему блокирует Windows/Program Files, WRP, Microsoft-signed, TrustedInstaller, reparse-point и критические процессные цели. Процесс нельзя завершить, если путь его исполняемого файла не совпадает с выбранным объектом.

## Запуск

1. Распакуйте `VoidGuard-v0.2.0-Portable.zip`.
2. Запустите `VoidGuard.cmd`.
3. Для remediation запустите CMD от администратора.
4. После scheduled deletion перезагрузите Windows и откройте `PENDING REMEDIATION LEDGER`.

> VoidGuard не заменяет Microsoft Defender, EDR или офлайн-проверку при подозрении на rootkit/PPL/bootkit.
