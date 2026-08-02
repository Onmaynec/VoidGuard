# Использование VoidGuard v0.2.0

## Интерактивный режим

```cmd
VoidGuard.cmd
```

Управление:

- `↑` / `↓` — выбор пункта;
- `Enter` — открыть;
- `Esc` — назад;
- `F1` — справка.

Новые разделы:

- `PERSISTENCE MATRIX` — службы, задачи, WMI и обычный автозапуск;
- `LOCKED FILE / SAFE REMEDIATION` — владельцы блокировки, карантин и удаление при загрузке;
- `PENDING REMEDIATION LEDGER` — проверка scheduled deletion после перезагрузки.

## Командные режимы

```powershell
# Быстрое сканирование
.\VoidGuard.ps1 -Mode QuickScan -Professional

# Сканирование файла или папки
.\VoidGuard.ps1 -Mode CustomScan -Path "C:\Users\User\Downloads"

# Состояние Windows security components
.\VoidGuard.ps1 -Mode Status -Json

# Анализ процессов
.\VoidGuard.ps1 -Mode Processes -Json

# Анализ persistence
.\VoidGuard.ps1 -Mode Persistence -Json

# Кто удерживает файл
.\VoidGuard.ps1 -Mode Locks -Path "C:\Suspicious\payload.exe" -Json

# Остановить точный процесс и попробовать карантин
.\VoidGuard.ps1 -Mode Remediate `
  -Path "C:\Suspicious\payload.exe" `
  -StopTargetProcess `
  -TargetProcessId 4242 `
  -Confirmed `
  -Json

# Если файл остаётся занятым — назначить удаление при загрузке
.\VoidGuard.ps1 -Mode Remediate `
  -Path "C:\Suspicious\payload.exe" `
  -ScheduleOnReboot `
  -Confirmed `
  -Json

# Проверить результат после перезагрузки
.\VoidGuard.ps1 -Mode Pending -Json

# Демонстрация визуальных эффектов без изменений системы
.\VoidGuard.ps1 -Mode Demo
```

## Remediation workflow

1. Выполните scan и изучите причины оценки.
2. Проверьте цифровую подпись и SHA-256.
3. Используйте `Locks`, чтобы определить владельцев блокировки.
4. Остановка процесса разрешена только для executable, который точно совпадает с выбранным файлом.
5. Попробуйте карантин.
6. Если файл нельзя переместить, назначьте удаление при следующей загрузке.
7. Перезагрузите Windows и выполните `Pending`.

## Интерпретация риска

- `LOW` — слабые эвристические признаки;
- `MEDIUM` — объект требует ручной проверки;
- `HIGH` — несколько серьёзных признаков;
- `CRITICAL` — известный вредоносный хеш или очень сильная комбинация признаков.

Эвристика может ошибаться. Не выполняйте remediation только из-за одного балла.
