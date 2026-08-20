# RU :: TCP 16-20 DPI & Hosting Checker ⚡

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Browser%20SPA-orange)](https://yanpurvenes.github.io/hosting-checker/)
[![Zero Backend](https://img.shields.io/badge/backend-Zero%20Dependencies-brightgreen)](#)
[![GitHub Pages Ready](https://img.shields.io/badge/deploy-GitHub%20Pages-success)](#)

Интерактивный браузерный инструмент для экспресс-диагностики и проверки доступности зарубежных и российских VPS/VDS-хостингов и CDN-сетей в условиях блокировок и ТСПУ/DPI-фильтрации методом **TCP 16-20**.

---

## 🌟 Основные возможности

* **100% Client-Side (Zero Dependencies):** Работает полностью в браузере через стандартный `fetch` API, не требует сервера, базы данных или сторонних библиотек.
* **Многопоточный движок тестирования:** Настраиваемое количество параллельных воркеров (от 1 до 12) и регулируемый таймаут запросов (1–15 сек).
* **Диагностика методом TCP 16-20 DPI:**
  * **Alive Check:** Проверка базовой доступности узла с замером RTT/latency.
  * **Method 1 (Huge Body POST):** Отправка 64 КБ псевдослучайных бинарных данных для провоцирования сброса соединения DPI-оборудованием.
  * **Method 2 (Huge URI reqline):** Отправка серии длинных URI-запросов через keep-alive соединения.
* **Встроенная база провайдеров (50+ хостов):**
  * **Зарубежные VPS:** Hetzner, OVH, AWS, Google Cloud, Azure, DigitalOcean, Vultr, Contabo, Netcup, UpCloud, Melbicom, BuyVM, Scaleway и др.
  * **Хостинги с РФ-корнями:** Selectel, RuVDS, FirstVDS, Aeza, PQ Hosting, Timeweb, Beget, Reg.ru, Hostkey, SpaceWeb, Sprinthost, Webnames, AdminVPS, Fornex, VDSina, Евробайт, Макхост и др.
  * **Зарубежные и российские CDN:** Cloudflare, Fastly, Akamai, CDN77, Gcore, Yandex CDN, VK CDN, EdgeCenter, Ngenix, CDNvideo, MTS CDN, MegaFon CDN.
* **Автоматическое определение провайдера:** Интеграция с RIPE NCC REST API (определение вашего внешнего IP, ASN, названия оператора и геопозиции).
* **Генерация ссылок на отчеты (Share Results):** Компактное кодирование результатов сканирования в URL (Base64) для быстрой отправки отчетов коллегам или в поддержку.
* **Диагностический лог в реальном времени:** Детальный журнал с точными таймстемпами и классификацией ответов.
* **Две темы оформления:** Современная тёмная тема со стеклянным эффектом (Glassmorphism) и классический светлый интерфейс.

---

## 🚀 Быстрый запуск

### Локально:
Просто откройте файл `index.html` в любом современном веб-браузере (Chrome, Firefox, Safari, Edge, Brave).

```bash
# Клонировать репозиторий
git clone https://github.com/yanpurvenes/hosting-checker.git

# Перейти в папку и открыть
cd hosting-checker
open index.html # для macOS
# или xdg-open index.html для Linux
# или start index.html для Windows
```

---

## 🌐 Развёртывание на GitHub Pages

Проект готов к мгновенной публикации через **GitHub Pages**:

1. Зайдите в ваш репозиторий на GitHub: `https://github.com/yanpurvenes/hosting-checker`.
2. Перейдите в **Settings** -> **Pages** (в боковом меню).
3. В секции **Build and deployment**:
   * **Source:** выберите `Deploy from a branch`.
   * **Branch:** выберите `main` и папку `/(root)`.
   * Нажмите **Save**.
4. Через 1 минуту чекер будет доступен онлайн по адресу:
   ```
   https://yanpurvenes.github.io/hosting-checker/
   ```

---

## ⚠️ Особенности работы в браузере

* Из-за песочницы браузера TCP-сокеты не могут быть принудительно разорваны кодом страницы, и браузер может кэшировать активные соединения.
* Для максимальной чистоты повторных тестов рекомендуется использовать **Режим инкогнито** либо сбрасывать пул сокетов в Chrome:
  `chrome://net-internals/#sockets` -> *Flush socket pools*.

---

## 📚 Благодарности и первоисточники

Методология и логика эвристических проверок TCP 16-20 основана на исследованиях сетевой доступности сообщества [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers).

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).
