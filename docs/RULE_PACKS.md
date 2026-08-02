# Rule packs и YARA

## Структура

Каждый pack находится в отдельном каталоге:

```text
Rules\Packs\my-pack\
 ├── manifest.json
 ├── detections.json
 └── custom.yar
```

Минимальный manifest:

```json
{
  "schemaVersion": 1,
  "id": "publisher.pack-name",
  "name": "Pack display name",
  "version": "1.0.0",
  "publisher": "Publisher name",
  "trustMode": "signed",
  "minimumVoidGuardVersion": "0.3.0",
  "files": [
    {
      "path": "detections.json",
      "sha256": "UPPERCASE_SHA256",
      "type": "pattern"
    },
    {
      "path": "custom.yar",
      "sha256": "UPPERCASE_SHA256",
      "type": "yara"
    }
  ],
  "signature": {
    "keyId": "publisher-key-v1",
    "algorithm": "RSA-SHA256",
    "value": "BASE64_SIGNATURE"
  }
}
```

## Проверки

VoidGuard отклоняет pack при любом из условий:

- schema не поддерживается;
- id/version имеют неверный формат;
- путь файла абсолютный;
- путь содержит сегмент `..`;
- итоговый путь выходит за пределы каталога pack;
- расширение файла не входит в `.json`, `.yar`, `.yara`;
- файл отсутствует;
- SHA-256 не совпадает;
- signature/key не проходят trust policy.

Невалидный pack отображается командой `-Mode RulePacks`, но его rules не загружаются.

## Trust modes

### bundled

Используется для packs, поставляемых внутри официального release archive VoidGuard. Целостность внутренних файлов всё равно проверяется по manifest.

Пользователь должен проверить `SHA256SUMS.txt` самого release archive до первого запуска.

### signed

Используется для внешнего pack. Ключ должен находиться в:

```text
Rules\trusted-publishers.json
```

Формат trust store:

```json
[
  {
    "keyId": "publisher-key-v1",
    "publisher": "Publisher name",
    "rsaXml": "<RSAKeyValue>...</RSAKeyValue>"
  }
]
```

VoidGuard проверяет detached RSA-SHA256 signature над canonical payload manifest.

Canonical payload состоит из строк:

```text
schemaVersion=<value>
id=<value>
name=<value>
version=<value>
publisher=<value>
trustMode=<value>
minimumVoidGuardVersion=<value>
file=<path>|<sha256>|<type>
```

Строки `file=` сортируются по `path` и соединяются LF (`\n`). Поле `signature` в payload не входит.

### local

Предназначен для локальной разработки. По умолчанию отключён:

```json
"allowUnsignedLocalRulePacks": false
```

Включение этого режима снижает доверие к результатам и не рекомендуется на рабочих системах.

## Pattern rules

`detections.json` содержит массив:

```json
[
  {
    "id": "EXAMPLE-001",
    "extensions": [".ps1", ".cmd"],
    "pattern": "(?i)example-regex",
    "score": 20,
    "reason": "Human-readable explanation.",
    "maxBytes": 1048576
  }
]
```

Regex создаётся с ограниченным временем выполнения. Rule добавляет evidence и score, но не инициирует remediation.

## YARA

VoidGuard ищет:

```text
yara64.exe
yara.exe
yara64
yara
```

Либо используется явный путь:

```json
"yaraExecutable": "C:\\Tools\\YARA\\yara64.exe"
```

Ограничения:

```json
"yaraTimeoutSeconds": 15,
"yaraMaxFileSizeBytes": 67108864
```

VoidGuard не скачивает YARA автоматически и не включает сторонний binary в Portable ZIP.

Проверка:

```powershell
.\VoidGuard.ps1 -Mode RulePacks -Json
.\VoidGuard.ps1 -Mode Yara -Path "C:\Suspicious\sample.exe" -Json
```

## Встроенный core pack

`voidguard.core` содержит defensive patterns для:

- Regsvr32 remote/scriptlet execution;
- Rundll32 JavaScript execution;
- MSHTA remote content;
- Certutil transfer/decode;
- BITSAdmin transfer;
- Scheduled Task persistence;
- WMI process creation;
- hidden PowerShell execution;
- Defender exclusion/tamper combinations.

Это статические индикаторы. Возможны ложные срабатывания.
