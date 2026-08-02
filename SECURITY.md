# Security Policy

## Назначение проекта

VoidGuard — защитная диагностическая утилита. Она не должна использоваться как универсальный механизм удаления файлов, завершения процессов или обхода Windows security boundaries.

## Защитные ограничения

VoidGuard v0.1.0 блокирует карантин для:

- Windows и Program Files;
- Windows Resource Protection файлов;
- файлов с действительной подписью Microsoft;
- файлов TrustedInstaller;
- директорий, корней дисков, symbolic links и reparse points.

Заблокированную политику нельзя обойти параметром `--force`.

## Сообщение об уязвимости

Не публикуйте детали эксплойта в открытом issue. Используйте GitHub Security Advisories репозитория.
