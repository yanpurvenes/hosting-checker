# RU :: TCP 16-20 DPI & Hosting Checker ⚡

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Browser%20SPA-orange)](https://yanpurvenes.github.io/hosting-checker/)
[![Zero Backend](https://img.shields.io/badge/backend-Zero%20Dependencies-brightgreen)](#)
[![Endpoints](https://img.shields.io/badge/endpoints-90%2B%20targets-purple)](#)
[![GitHub Pages Ready](https://img.shields.io/badge/deploy-GitHub%20Pages-success)](#)

Интерактивный браузерный инструмент для комплексной экспресс-диагностики доступности зарубежных и российских VPS/VDS-хостингов, CDN-сетей, push-уведомлений и популярных интернет-сервисов в условиях блокировок и ТСПУ/DPI-фильтрации методом **TCP 16-20**.

Создан с учетом наработок и актуальных баз проекта [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers).

---

## 🌟 Ключевые возможности

* **100% Client-Side (Zero Dependencies):**
  * Работает полностью в браузере через чистый JavaScript (Vanilla ES6+) и Fetch API.
  * Никаких серверов, бэкендов, npm-пакетов или сборщиков — чистый автономный HTML/CSS/JS.
* **Расширенная база целей (90+ ресурсов по 8 категориям):**
  * **Популярные сервисы (`popular-services`):** YouTube (Web, Image CDN, Video Stream), Google (Web, Gstatic, Gemini AI), Telegram (Web, API), Discord, GitHub (Web, API, Raw Content), X (Twitter), Facebook, WhatsApp Web, Instagram, LinkedIn, Госуслуги, Яндекс, VK.
  * **Push-уведомления (`mobile-push`):** Сервисы доставки мобильных push-уведомлений Android и iOS — Google FCM, Mtalk, Accounts, IID, Android APIs, Firebase Installations, Apple APNs (Production и Sandbox).
  * **Зарубежные VPS (`foreign-vps`):** Hetzner (DE, FI), OVH, AWS (DE, US), Google Cloud, Microsoft Azure, DigitalOcean (DE, UK), Vultr (DE, US), Contabo, Netcup, UpCloud, Melbicom, BuyVM, Scaleway, Hostinger, SiteGround, IONOS, Kamatera, Linode/Akamai и др. (с обновленными живыми эндпоинтами из `suite.v2.json`).
  * **Хостинги и облака РФ (`rf-roots`):** Selectel, Yandex Cloud, Cloud.ru, VK Cloud, Ростелеком / DataLine, MTS Cloud / MWS, Softline Cloud, Timeweb, Beget, RuVDS, FirstVDS, AdminVPS, IHC.ru, Contell, Start2 / Netrack, DataHouse / Filanco, DDoS-Guard, LandVPS, RuFox, Fornex, VDSina, Евробайт, Макхост и др. (с активным тестированием TCP 16-20).
  * **Зарубежные CDN (`foreign-cdn`):** Cloudflare, Fastly, Akamai, CDN77, Gcore, GitHub Pages.
  * **Российские CDN (`rf-cdn`):** Yandex CDN, VK CDN, EdgeCenter CDN, Ngenix, CDNvideo, MTS CDN, MegaFon CDN.
  * **Infomaniak (`infomaniak`):** Выделенная категория для хостинга Infomaniak.
* **Онлайн-трассировка маршрутов (Live Traceroute & CLI):**
  * Встроенный интерактивный терминал сетевой трассировки маршрутов через распределенные зонды (в т.ч. прямо из РФ) к Infomaniak, Hetzner, OVH, DigitalOcean, AWS, Cloudflare с возможностью мгновенного копирования вывода (`Copy Output`).
  * Консольная Python-утилита `trace_hosting.py` для глубокой L4/L7 диагностики, выявления DPI/ТСПУ блокировок и пошаговой BGP/ASN трассировки без раскрытия клиентского IP.
* **Селектор провайдеров (Provider Selector Dropdown):**
  * Выпадающее интерактивное меню с поисковым фильтром.
  * Возможность включить/выключить отдельных провайдеров (кнопки «Выбрать все» и «Снять все»).
  * Позволяет запускать прицельные тесты конкретных сервисов без необходимости сканировать весь пул хостов.
* **Добавление своих хостов (Custom Targets):**
  * Добавление любого домена или IP через удобное всплывающее окно (кнопка «➕ Хост»).
  * Поддержка параметров в строке запроса (URL Query Params):
    * `?host=example.com&provider=MyVPS` — автоматическое добавление целевого узла при открытии страницы.
    * `?timeout=15` — задание таймаута сканирования по умолчанию.
* **Улучшенная диагностика ошибок и причин недоступности:**
  * **SNI RST (Connection Reset):** Мгновенный сброс TCP/TLS соединения (<600 мс), типичный для ТСПУ при обнаружении заблокированного SNI в пакете ClientHello.
  * **Timeout / Blackhole:** Сброс пакетов (черная дыра) или глухой таймаут при попытке соединения.
  * **Net Error / TLS Error:** Прочие сетевые и сертификатные ошибки.
* **Экспорт и обмен результатами (Export & Share):**
  * 📄 **Скачать JSON:** Полный машиночитаемый дамп со всеми метаданными, ASN клиента, временными метками, задержками (RTT) и статусами.
  * 📊 **Скачать CSV:** Табличный отчет в формате CSV (Excel-ready с разделителем `;` и UTF-8 BOM).
  * 🔗 **Share URL:** Кодирование полного снимка состояния в Base64 URL для мгновенной отправки коллегам или в тикеты провайдера.
* **Автоматическое определение ASN и провайдера:**
  * Определение внешнего IP, номера автономной системы (ASN), названия оператора связи и геолокации через REST API RIPE NCC.
* **Премиальный дизайн и переключение тем:**
  * Современная темная тема с эффектом глассморфизма (Glassmorphism), неоновыми акцентами и анимациями.
  * Классическая светлая тема в стиле оригинального инструмента Hyperion.

---

## 🔬 Принцип работы проверок TCP 16-20 DPI

Блокировки ТСПУ (технических средств противодействия угрозам) в РФ часто классифицируют трафик не по первому пакету, а с задержкой — на 16-20 пакете TCP-сессии или при передаче объема данных свыше определенного порога (обычно 64 КБ):

1. **Alive Check (Базовая доступность):** Отправляется легковесный HEAD-запрос для проверки установления TLS-сессии и замера задержки (RTT).
2. **Method 1 (Huge Body POST):** В рамках TLS-сессии передается 64 КБ бинарных данных случайного содержания (`getRandomValues`). Если ТСПУ блокирует передачу после накопления трафика, сессия обрывается по таймауту -> фиксируется **Detected❗️**.
3. **Method 2 (Huge URI Reqline):** Серия быстрых запросов с длинными URI через keep-alive соединение для суммирования 64 КБ данных. Фиксирует эвристику сброса при непрерывных транзакциях.

---

## 🚀 Быстрый запуск

### Локальный просмотр:
Просто откройте `index.html` в любом браузере:

```bash
git clone https://github.com/yanpurvenes/hosting-checker.git
cd hosting-checker
open index.html # для macOS
# или
python3 -m http.server 8080
```

### Развёртывание на GitHub Pages:
1. Перейдите в **Settings** вашего репозитория -> **Pages**.
2. В блоке **Build and deployment** укажите:
   * **Source:** `Deploy from a branch`
   * **Branch:** `main`, папка `/ (root)`
3. Нажмите **Save**. Страница будет опубликована по адресу:
   ```
   https://yanpurvenes.github.io/hosting-checker/
   ```

---

## 💡 Рекомендации для проведения тестов

1. **Режим инкогнито:** Браузерные сокеты переиспользуются между запросами в рамках пула соединений. Для чистоты экспериментов рекомендуется открывать тест в приватном окне.
2. **Очистка пула сокетов:** В браузерах на базе Chromium (Chrome, Edge, Brave, Яндекс.Браузер) можно вручную сбросить сокеты по ссылке:
   `chrome://net-internals/#sockets` -> нажмите кнопку **Flush socket pools**.

---

## 📚 Благодарности и первоисточники

Логика эвристических проверок TCP 16-20 и исходная методология основаны на исследованиях команды [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers).

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).
