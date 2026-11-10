# Threat Intelligence — VoidGuard v0.5.0

## Назначение

Threat Intelligence объединяет два действия, которые раньше приходилось выполнять вручную: обновление проверенных правил обнаружения и сбор данных для последующего разбора инцидента. Обновление правил не влияет на карантин или права запуска системных процессов.

## 1. Signed Rule Updates

Для установки подходит только каталог с `manifest.json`, файлами pattern/YARA и корректной RSA-SHA256 подписью manifest. Каталог должен быть уже распакован. Программа не скачивает обновления сама и не импортирует публичные ключи без владельца компьютера.

Перед первым импортом необходимо независимо проверить происхождение ключа издателя и добавить его в `Rules/trusted-publishers.json`. Исходный файл в репозитории содержит `[]`. Отсутствие доверенного ключа означает отказ в установке.

### Проверить обновление

```powershell
.\VoidGuard.ps1 -Mode RuleUpdate -UpdateSource "C:\Updates\example.rules" -Json
```

В результате доступны ID, текущая и новая версии, publisher, keyId, ожидаемая операция, состав файлов, размер и причина отказа. Предпросмотр ничего не устанавливает.

### Установить и включить

```powershell
.\VoidGuard.ps1 -Mode RuleUpdate -UpdateSource "C:\Updates\example.rules" -Confirmed -Json
.\VoidGuard.ps1 -Mode RuleActivate -RulePackId "example.rules" -Enable -Confirmed -Json
```

Установка не включает новый пакет автоматически. Подписанные rules участвуют в scan только после включения. Новая версия заменяет старую при совпадении ID, издателя и ключа, а старый каталог перемещается в локальную историю.

### Посмотреть историю и откатиться

```powershell
.\VoidGuard.ps1 -Mode RuleHistory -RulePackId "example.rules" -Json
.\VoidGuard.ps1 -Mode RuleRollback -RulePackId "example.rules" -HistoryId "h-20261110120000-abc123def456" -Confirmed -Json
```

History ID берётся из реального результата RuleHistory; приведённый выше ID служит примером. При откате выбранная версия повторно проверяется, а текущая подписанная версия архивируется. Встроенный `voidguard.core` не может быть установлен или откатан этим механизмом. Для отмены установки/отката до записи используйте `-WhatIf`.

### Ограничения

Поддерживается до 16 файлов правил, каждый до 10 МиБ, общий размер до 25 МиБ. Не разрешены символические ссылки, reparse points, вложенные папки или посторонние файлы. Обновление не выполняется при несовпадении подписи, хеша, keyId, при попытке downgrade или замене неподписанного текущего pack.

Файлы внутри пользовательской папки VoidGuard не обладают аппаратно защищённой неизменностью. Если сторонний процесс уже может редактировать исходники и trust store приложения, защита подписью внутри него не является достаточной.

## 2. Incident Bundle

Данные в архиве собираются из уже реализованных диагностических модулей. Экспорт ничего не отправляет в интернет и не запускает remediation.

### Предпросмотр без записи

```powershell
.\VoidGuard.ps1 -Mode IncidentPreview -IncidentPath "C:\Temp\incident.zip" -Json
```

Предпросмотр перечисляет будущие категории и предупреждает о приватности. Это не завершённый сбор и не подтверждение доступности всех источников.

### Стандартный экспорт

```powershell
.\VoidGuard.ps1 -Mode IncidentExport -IncidentPath "C:\Temp\incident.zip" -Confirmed -Json
```

По умолчанию входят: сводка Defender и Firewall, перечень версий правил, сведения об обнаруженных подозрительных процессах и persistence, статусы pending. Имена компьютера, сырые пути, команды запуска, сетевые адреса и сообщения событий по умолчанию исключены. Предел выдачи — 100 находок на тип.

### Дополнительные источники

```powershell
# Скан указанного файла и последние события Defender
.\VoidGuard.ps1 -Mode IncidentExport -IncidentPath "C:\Temp\incident-with-scan.zip" -IncidentScanPath "C:\Temp\sample.ps1" -IncludeEventLogs -Confirmed -Json

# Сравнить System Integrity с ранее сделанным snapshot
.\VoidGuard.ps1 -Mode IncidentExport -IncidentPath "C:\Temp\incident-with-baseline.zip" -IncidentBaselinePath "C:\Temp\baseline.json" -Confirmed -Json

# Включить сырые технические поля и полные сообщения событий
.\VoidGuard.ps1 -Mode IncidentExport -IncidentPath "C:\Temp\incident-sensitive.zip" -IncludeEventLogs -IncludeSensitive -Confirmed -Json
```

События берутся из Microsoft-Windows-Windows Defender/Operational: не больше 100 за последние 7 дней. При отсутствии прав или канала результат PARTIAL. Пропущенные и недоступные источники не считаются успешно собранными.

### Проверка архива

В ZIP три файла: `diagnostics.json`, `manifest.json` и `SHA256SUMS.txt`. SHA256SUMS проверяет JSON внутри архива; SHA-256 самого ZIP возвращается командой. Существующий путь назначения не перезаписывается. Максимальный размер ZIP — 25 МиБ.

Перед передачей архива третьим лицам внимательно проверьте `diagnostics.json`. Даже редактированный стандартный отчёт может раскрывать перечень установленного ПО. Режим `IncludeSensitive` следует использовать только при действительно необходимой детальной диагностике.
