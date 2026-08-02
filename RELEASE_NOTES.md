# VOIDGUARD v0.3.0 — SIGNATURE GRID

Третья публичная версия добавляет проверяемый rule engine, опциональную YARA-интеграцию, расширенный PE-анализ и автономные отчёты.

## Главное

- `Rules/Packs` получает manifest-based trust model;
- каждый файл pack проверяется по SHA-256 до загрузки;
- внешние packs могут использовать detached RSA-SHA256 подпись и локальный trust store;
- неподписанные local packs запрещены по умолчанию;
- встроенный `voidguard.core` содержит defensive regex и YARA rules для LOLBin, persistence и Defender tamper patterns;
- Quick/Custom Scan автоматически объединяет metadata, Authenticode, PE, entropy, rule-pack и YARA evidence;
- PE parser показывает архитектуру, число секций и compile timestamp;
- PE-содержимое с неисполняемым расширением получает отдельный сильный сигнал;
- HTML/JSON reports создаются полностью офлайн и экранируют данные находок;
- новые CLI-режимы: `RulePacks`, `Yara`, `-ReportPath`, `-ReportFormat`.

## YARA

YARA CLI не включён в release и не скачивается автоматически. VoidGuard использует только установленный пользователем `yara.exe` или `yara64.exe`. При его отсутствии основной scan engine продолжает работать без ошибки.

## Trust boundary

Rule packs и reports не получают полномочий remediation. Они только добавляют объяснимые evidence к результату. Карантин, process stop и delete-on-reboot по-прежнему проходят отдельные backend policy checks.

## Запуск

1. Распакуйте `VoidGuard-v0.3.0-Portable.zip`.
2. Запустите `VoidGuard.cmd` для обычного TUI.
3. Посмотрите активные packs: `.\VoidGuard.ps1 -Mode RulePacks -Json`.
4. Создайте отчёт: `.\VoidGuard.ps1 -Mode QuickScan -ReportPath .\Reports\quick -ReportFormat Both`.

> VoidGuard не заменяет Microsoft Defender, EDR или офлайн-проверку при подозрении на rootkit/PPL/bootkit.
