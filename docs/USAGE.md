# Использование VoidGuard

## Интерактивный режим

```cmd
VoidGuard.cmd
```

Управление:

- `↑` / `↓` — выбор пункта;
- `Enter` — открыть;
- `Esc` — назад;
- `F1` — справка.

## Командные режимы

```powershell
# Быстрое сканирование
.\VoidGuard.ps1 -Mode QuickScan -Professional

# Сканирование файла или папки
.\VoidGuard.ps1 -Mode CustomScan -Path "C:\Users\User\Downloads"

# JSON-отчёт
.\VoidGuard.ps1 -Mode QuickScan -Professional -NoAnimation -Json

# Состояние Windows security components
.\VoidGuard.ps1 -Mode Status -Json

# Демонстрация визуальных эффектов без изменений системы
.\VoidGuard.ps1 -Mode Demo
```

## Интерпретация результата

- `LOW` — слабые эвристические признаки;
- `MEDIUM` — объект требует ручной проверки;
- `HIGH` — несколько серьёзных признаков;
- `CRITICAL` — известный вредоносный хеш или очень сильная комбинация признаков.

Эвристика может ошибаться. Не помещайте файл в карантин только из-за одного балла.
