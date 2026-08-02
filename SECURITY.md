# Security Policy

## Назначение проекта

VoidGuard — защитная диагностическая утилита. Она не должна использоваться как универсальный механизм удаления файлов, завершения процессов или обхода Windows security boundaries.

## Защитные ограничения

VoidGuard v0.2.0 блокирует quarantine/remediation для:

- Windows и Program Files;
- Windows Resource Protection файлов;
- файлов с действительной подписью Microsoft;
- файлов TrustedInstaller;
- директорий, корней дисков, symbolic links и reparse points;
- критических процессов Windows;
- процессов, executable path которых не совпадает с canonical path цели.

Заблокированную policy нельзя обойти параметром `--force`: такого параметра в проекте нет.

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
- выйти из quarantine directory;
- выполнить произвольную команду через persistence parser;
- изменить release assets после публикации без обнаружения.

## Сообщение об уязвимости

Не публикуйте детали эксплойта в открытом issue. Используйте GitHub Security Advisories репозитория.
