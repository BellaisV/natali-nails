@echo off
title Natali Nails Prive - CRM & VIP Club
echo ========================================================
echo          NATALI NAILS PRIVE - BEAUTY CRM
echo ========================================================
echo.
echo 1. Кабінет майстра Natali:
echo    http://localhost:8000
echo.
echo 2. Сторінка онлайн-запису для Instagram:
echo    http://localhost:8000/book
echo.
echo 3. VIP-клуб клієнток (бали, смайлики, вхід через Instagram/Facebook):
echo    http://localhost:8000/club
echo.
echo Методи оплати: Bizum, Карти, PayPal, Готівка
echo Валюти: EUR (€) / UAH (грн)
echo Мови: Українська, English, Espanol, Valencia, Deutsch, Русский
echo.
echo Для зупинки сервера закрийте це вікно
echo ========================================================
echo.
start http://localhost:8000
python -m uvicorn server:app --host 0.0.0.0 --port 8000
pause
