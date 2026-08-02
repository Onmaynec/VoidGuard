# Offline reports

VoidGuard v0.3.0 может сохранять результат анализа в JSON, HTML или оба формата.

## Создание

```powershell
.\VoidGuard.ps1 -Mode QuickScan `
  -ReportPath ".\Reports\quick-scan" `
  -ReportFormat Both
```

Варианты `-ReportFormat`:

- `Json`;
- `Html`;
- `Both`.

Если расширение не указано, VoidGuard добавляет `.json` и/или `.html`.

## JSON envelope

```json
{
  "schemaVersion": 1,
  "product": "VoidGuard",
  "version": "0.3.0",
  "generatedUtc": "2026-08-02T10:00:00.0000000Z",
  "computerName": "HOST",
  "reportKind": "Quick",
  "data": {}
}
```

Поле `data` содержит исходный объект результата, включая findings, rule-pack inventory и статус YARA.

## HTML

HTML report содержит:

- metadata и summary;
- таблицу findings;
- Risk и Score;
- Path/Command;
- Authenticode status;
- Entropy;
- SHA-256;
- YARA matches;
- объяснимые Reasons.

## Privacy и безопасность

HTML report:

- работает офлайн;
- не содержит JavaScript;
- не загружает CSS, fonts, images или analytics;
- HTML-экранирует пути, причины и значения находок;
- может содержать чувствительные локальные пути, имена хостов и сведения о процессах.

Перед отправкой report третьей стороне проверьте его содержимое.

## Примеры

```powershell
# Только HTML
.\VoidGuard.ps1 -Mode CustomScan `
  -Path "C:\Downloads" `
  -ReportPath ".\Reports\downloads.html" `
  -ReportFormat Html

# JSON security status
.\VoidGuard.ps1 -Mode Status `
  -ReportPath ".\Reports\security-status.json" `
  -ReportFormat Json

# Persistence report
.\VoidGuard.ps1 -Mode Persistence `
  -ReportPath ".\Reports\persistence" `
  -ReportFormat Both
```

## Проверка целостности

Report не подписывается VoidGuard и не является неизменяемым доказательством. Для incident workflow рекомендуется сразу вычислить SHA-256:

```powershell
Get-FileHash .\Reports\quick-scan.json -Algorithm SHA256
Get-FileHash .\Reports\quick-scan.html -Algorithm SHA256
```
