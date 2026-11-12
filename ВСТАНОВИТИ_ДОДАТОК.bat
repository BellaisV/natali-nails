@echo off
chcp 65001 >nul
title Встановлення Natali Nails Privé CRM
echo ========================================================
echo       ВСТАНОВЛЕННЯ СИСТЕМИ NATALI NAILS PRIVÉ CRM
echo ========================================================
echo.
echo [1/3] Перевірка та встановлення бібліотек Python...
python -m pip install -r requirements.txt
echo.
echo [2/3] Створення розкішного ярлика на Робочому столі...
python create_shortcut.py
echo.
echo [3/3] Запуск системи...
echo.
echo Встановлення завершено успішно!
echo.
echo Зараз відкриється кабінет майстра Natali...
timeout /t 2 >nul
start http://localhost:8000
python -m uvicorn server:app --host 0.0.0.0 --port 8000
pause
