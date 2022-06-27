--
-- Файл сгенерирован с помощью SQLiteStudio v3.3.3 в Вт июн 28 00:36:46 2022
--
-- Использованная кодировка текста: UTF-8
--
PRAGMA foreign_keys = off;
BEGIN TRANSACTION;

-- Таблица: http
CREATE TABLE http (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT);

-- Таблица: mail
CREATE TABLE "mail" (
	"id"	INTEGER,
	"domain"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);

-- Таблица: malware_email
CREATE TABLE malware_email (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT);

-- Таблица: malware_http
CREATE TABLE malware_http (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT);

COMMIT TRANSACTION;
PRAGMA foreign_keys = on;
