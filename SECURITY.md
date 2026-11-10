# Security Policy

## Назначение проекта

VoidGuard — защитная диагностическая утилита. Она не должна использоваться как универсальный механизм удаления файлов, завершения процессов или обхода Windows security boundaries.

## Защитные ограничения remediation

VoidGuard v0.3.4 блокирует quarantine/remediation для:

- Windows и Program Files;
- Windows Resource Protection файлов;
- файлов с действительной подписью Microsoft;
- файлов TrustedInstaller;
- директорий, корней дисков, symbolic links и reparse points;
- критических процессов Windows;
- процессов, executable path которых не совпадает с canonical path цели.

Заблокированную policy нельзя обойти параметром `--force`: такого параметра в проекте нет.

## Rule-pack security

До загрузки pack проверяются schema, относительные пути и SHA-256 каждого файла. Файл правила не может быть absolute path, содержать `..` или выходить из каталога pack.

- `signed` packs требуют RSA-SHA256 signature и ключ из локального trust store;
- `local` packs запрещены по умолчанию;
- невалидные packs остаются видимыми в inventory, но не используются scanner;
- rules влияют только на evidence/score и не вызывают quarantine/remediation;
- VoidGuard не загружает YARA binary или packs из сети автоматически.
- режим `bundled` доверяет только закреплённому core pack с проверяемыми метаданными и SHA-256 файлов;
- reparse points в каталоге pack, manifest и файлах правил блокируются.

`bundled` означает, что pack поставляется внутри release archive. Проверяйте SHA256SUMS release перед первым запуском.

## Восстановление из карантина

Перед восстановлением проверяются схема, ID, размер и SHA-256 payload. Подменённые данные, reparse points в пути и защищённые каталоги блокируются. Если путь назначения занят, восстановление по умолчанию запрещено. Проверка целостности не защищает от полного изменения установленного кода программы привилегированным пользователем.

## Report security

HTML reports:

- HTML-экранируют значения находок;
- не содержат JavaScript;
- не используют внешние CSS, fonts, images, analytics или network requests;
- не должны открываться как доверенная инструкция по remediation без проверки исходного объекта.

## Привилегированные операции

- остановка процесса требует `-Confirmed` и повторной проверки точного executable path;
- удаление при загрузке требует администратора, `-Confirmed`, SHA-256 snapshot и запись в pending ledger;
- quarantine требует явного подтверждения для каждого файла;
- TUI не считается доверенной границей: backend-модули повторяют проверки непосредственно перед действием.

## Уязвимости высокой важности

Особенно важны сообщения о возможности:

- удалить Windows/Microsoft/WRP/TrustedInstaller файл;
- завершить произвольный или критический процесс;
- подменить проверенный путь через symlink/reparse point или race condition;
- выйти из quarantine или rule-pack directory;
- загрузить pack с неверным SHA-256 или недействительной RSA-подписью;
- выполнить произвольную команду через rule/persistence parser;
- внедрить active content в HTML report;
- изменить release assets после публикации без обнаружения.

## Сообщение об уязвимости

Не публикуйте детали эксплойта в открытом issue. Используйте GitHub Security Advisories репозитория.
