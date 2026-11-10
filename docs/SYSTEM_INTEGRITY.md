# System Integrity — VoidGuard v0.4.0

## Назначение

Снимок фиксирует параметры Windows, а сравнение показывает, какие настройки изменились. Добавление службы, изменение автозапуска или файла не означает автоматически заражения: причиной могут быть установки и обновления.

## Состав данных

- **Security** — Defender, исключения, Firewall, UAC, SmartScreen, прокси.
- **Services** — имя, путь запуска, режим, аккаунт, тип.
- **Tasks** — задания планировщика, команды, аргументы, триггеры.
- **Startup** — доступные записи автозапуска и Startup folders.
- **Files** — SHA-256 и размер файлов, hosts по умолчанию.

## Использование

```powershell
# Записать baseline в папку VoidGuard пользователя
.\VoidGuard.ps1 -Mode BaselineCreate -Json

# Записать только файл в выбранный JSON
.\VoidGuard.ps1 -Mode BaselineCreate -BaselinePath "C:\Temp\file-baseline.json" -IntegritySections Files -IntegrityPaths "C:\Temp\sample.exe" -NoHosts -Json

# Сравнить
.\VoidGuard.ps1 -Mode BaselineDiff -BaselinePath "C:\Temp\file-baseline.json" -Json
```

Результат UNCHANGED — полный сбор без изменений, CHANGED — найдены различия, PARTIAL — не все данные собраны. Неполные разделы не сравниваются. Максимум 128 выбранных файлов, лимит одного файла 256 МиБ; максимальный размер baseline для чтения 10 МиБ. Существующий baseline не перезаписывается.

## Microsoft Defender Offline

```powershell
# Предпросмотр, без перезагрузки
.\VoidGuard.ps1 -Mode DefenderOffline -Json

# Запуск — только после ручной подготовки
.\VoidGuard.ps1 -Mode DefenderOffline -Confirmed -RebootAcknowledged
```

В TUI требуются два подтверждения: OFFLINE и RESTART. Проверяются Windows, права, WinRE, Microsoft Defender и BitLocker. Активная защита BitLocker блокирует запуск до ручной подготовки: сохраните ключ восстановления и ознакомьтесь с официальным руководством. VoidGuard не отключает шифрование автоматически.

Start-MpWDOScan может немедленно перезагрузить компьютер. Результаты после возврата в Windows ищите в журнале защиты Windows Security.

Официальная документация:
- https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-offline
- https://learn.microsoft.com/en-us/powershell/module/defender/start-mpwdoscan

## Безопасность

Baseline содержит локальные пути и команды. Не публикуйте полный JSON в открытых Issues. Доверенную копию следует хранить вне проверяемой системы: формат JSON v1 не имеет криптографической подписи.
