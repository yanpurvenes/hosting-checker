#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Аудит 100 зарубежных и европейских хостинг-провайдеров через API Cheburcheck.ru
Проверяет наличие IP/доменов в реестрах блокировок Роскомнадзора (РКН)
и списках заблокированных CDN/хостингов (123jjck/cdn-ip-ranges, antifilter).
"""

import sys
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, List

TARGETS: List[Dict[str, str]] = [
    # === 1. НИДЕРЛАНДЫ (NL) — 14 узлов ===
    {"id": "NL-01", "name": "Tilaa (Amsterdam)", "target": "84.22.115.3", "country": "🇳🇱 NL", "loc": "Амстердам"},
    {"id": "NL-02", "name": "Leaseweb (Mirror AMS)", "target": "5.79.108.33", "country": "🇳🇱 NL", "loc": "Амстердам"},
    {"id": "NL-03", "name": "Leaseweb (Looking Glass)", "target": "136.144.200.162", "country": "🇳🇱 NL", "loc": "Амстердам"},
    {"id": "NL-04", "name": "TransIP (BladeVPS)", "target": "37.97.254.1", "country": "🇳🇱 NL", "loc": "Амстердам / Лейден"},
    {"id": "NL-05", "name": "LiteServer (Alphen)", "target": "185.31.172.236", "country": "🇳🇱 NL", "loc": "Альфен-ан-ден-Рейн"},
    {"id": "NL-06", "name": "HostHatch (Amsterdam)", "target": "185.223.30.22", "country": "🇳🇱 NL", "loc": "Амстердам (Equinix)"},
    {"id": "NL-07", "name": "Serverius (DC1/DC2)", "target": "178.21.16.2", "country": "🇳🇱 NL", "loc": "Апелдорн / Меппель"},
    {"id": "NL-08", "name": "Worldstream (Naaldwijk)", "target": "217.23.0.1", "country": "🇳🇱 NL", "loc": "Наалдвейк"},
    {"id": "NL-09", "name": "NovoServe (Doetinchem)", "target": "84.244.24.1", "country": "🇳🇱 NL", "loc": "Дутинхем"},
    {"id": "NL-10", "name": "Snel.com (SmartDC)", "target": "89.207.131.250", "country": "🇳🇱 NL", "loc": "Роттердам"},
    {"id": "NL-11", "name": "Duocast (Groningen)", "target": "94.124.136.1", "country": "🇳🇱 NL", "loc": "Гронинген"},
    {"id": "NL-12", "name": "NFOrce Entertainment", "target": "85.159.239.1", "country": "🇳🇱 NL", "loc": "Амстердам"},
    {"id": "NL-13", "name": "Dataplace (Alblasserdam)", "target": "194.145.200.1", "country": "🇳🇱 NL", "loc": "Альблассердам"},
    {"id": "NL-14", "name": "Clouvider (Amsterdam)", "target": "194.127.172.1", "country": "🇳🇱 NL", "loc": "Амстердам"},

    # === 2. ГЕРМАНИЯ (DE) — 13 узлов ===
    {"id": "DE-01", "name": "Hetzner Falkenstein (FSN1)", "target": "78.46.170.2", "country": "🇩🇪 DE", "loc": "Фалькенштайн"},
    {"id": "DE-02", "name": "Hetzner Nuremberg (NBG1)", "target": "78.47.119.196", "country": "🇩🇪 DE", "loc": "Нюрнберг"},
    {"id": "DE-03", "name": "Netcup (Anexia)", "target": "46.38.224.30", "country": "🇩🇪 DE", "loc": "Карлсруэ / Нюрнберг"},
    {"id": "DE-04", "name": "Contabo (Munich)", "target": "13.140.169.107", "country": "🇩🇪 DE", "loc": "Мюнхен / Нюрнберг"},
    {"id": "DE-05", "name": "Strato (Berlin)", "target": "81.169.145.161", "country": "🇩🇪 DE", "loc": "Берлин"},
    {"id": "DE-06", "name": "IONOS / 1&1 (Frankfurt)", "target": "217.160.0.1", "country": "🇩🇪 DE", "loc": "Франкфурт"},
    {"id": "DE-07", "name": "Keyweb (Thuringia)", "target": "84.19.160.1", "country": "🇩🇪 DE", "loc": "Эрфурт"},
    {"id": "DE-08", "name": "Webtropia / myLoc", "target": "62.138.0.1", "country": "🇩🇪 DE", "loc": "Дюссельдорф"},
    {"id": "DE-09", "name": "AlphaVPS (Nuremberg)", "target": "194.35.12.68", "country": "🇩🇪 DE", "loc": "Нюрнберг"},
    {"id": "DE-10", "name": "ServerCow (Frankfurt)", "target": "185.12.64.1", "country": "🇩🇪 DE", "loc": "Франкфурт"},
    {"id": "DE-11", "name": "Manitu (St. Wendel)", "target": "217.11.48.1", "country": "🇩🇪 DE", "loc": "Санкт-Вендель"},
    {"id": "DE-12", "name": "IP-Projects (Frankfurt)", "target": "5.9.0.1", "country": "🇩🇪 DE", "loc": "Франкфурт"},
    {"id": "DE-13", "name": "Host Europe (Cologne)", "target": "80.237.132.1", "country": "🇩🇪 DE", "loc": "Кельн"},

    # === 3. ФИНЛЯНДИЯ (FI) — 6 узлов ===
    {"id": "FI-01", "name": "UpCloud (Helsinki)", "target": "94.237.1.53", "country": "🇫🇮 FI", "loc": "Хельсинки"},
    {"id": "FI-02", "name": "Hetzner Helsinki (HEL1)", "target": "95.217.255.81", "country": "🇫🇮 FI", "loc": "Хельсинки"},
    {"id": "FI-03", "name": "Webdock (Helsinki)", "target": "185.105.4.1", "country": "🇫🇮 FI", "loc": "Хельсинки (Equinix)"},
    {"id": "FI-04", "name": "Creanova (Helsinki)", "target": "185.40.4.1", "country": "🇫🇮 FI", "loc": "Хельсинки"},
    {"id": "FI-05", "name": "Verne Global (Pori)", "target": "194.14.80.1", "country": "🇫🇮 FI", "loc": "Пори"},
    {"id": "FI-06", "name": "Zoner (Helsinki)", "target": "185.87.110.1", "country": "🇫🇮 FI", "loc": "Хельсинки"},

    # === 4. ШВЕЦИЯ, НОРВЕГИЯ, ДАНИЯ (SE / NO / DK) — 9 узлов ===
    {"id": "SE-01", "name": "GleSYS (Stockholm)", "target": "159.253.0.1", "country": "🇸🇪 SE", "loc": "Стокгольм"},
    {"id": "SE-02", "name": "Bahnhof (Stockholm)", "target": "82.145.208.1", "country": "🇸🇪 SE", "loc": "Стокгольм (Pionen)"},
    {"id": "SE-03", "name": "HostHatch (Stockholm)", "target": "31.220.7.200", "country": "🇸🇪 SE", "loc": "Стокгольм"},
    {"id": "SE-04", "name": "Obenetwork (Stockholm)", "target": "194.242.110.1", "country": "🇸🇪 SE", "loc": "Стокгольм"},
    {"id": "SE-05", "name": "Internetport (Hudiksvall)", "target": "80.244.64.1", "country": "🇸🇪 SE", "loc": "Худиксвалль"},
    {"id": "NO-01", "name": "HostHatch (Oslo)", "target": "185.223.31.22", "country": "🇳🇴 NO", "loc": "Осло"},
    {"id": "NO-02", "name": "Pro ISP (Stavanger)", "target": "185.91.52.1", "country": "🇳🇴 NO", "loc": "Ставангер"},
    {"id": "DK-01", "name": "Webdock (Aarhus/Copenhagen)", "target": "185.204.0.1", "country": "🇩🇰 DK", "loc": "Орхус"},
    {"id": "DK-02", "name": "Simply.com (Skanderborg)", "target": "185.129.60.1", "country": "🇩🇰 DK", "loc": "Сканнерборг"},

    # === 5. ФРАНЦИЯ (FR) — 9 узлов ===
    {"id": "FR-01", "name": "OVHcloud (Roubaix)", "target": "188.165.254.16", "country": "🇫🇷 FR", "loc": "Рубе"},
    {"id": "FR-02", "name": "OVHcloud (Gravelines)", "target": "51.255.100.1", "country": "🇫🇷 FR", "loc": "Гравелин"},
    {"id": "FR-03", "name": "OVHcloud (Strasbourg)", "target": "51.38.160.1", "country": "🇫🇷 FR", "loc": "Страсбург"},
    {"id": "FR-04", "name": "Scaleway (Paris)", "target": "51.159.0.1", "country": "🇫🇷 FR", "loc": "Париж"},
    {"id": "FR-05", "name": "Ikoula (Reims)", "target": "213.246.32.1", "country": "🇫🇷 FR", "loc": "Реймс"},
    {"id": "FR-06", "name": "Online.net / Dedibox", "target": "62.210.0.1", "country": "🇫🇷 FR", "loc": "Париж"},
    {"id": "FR-07", "name": "O2Switch (Clermont)", "target": "109.234.160.1", "country": "🇫🇷 FR", "loc": "Клермон-Ферран"},
    {"id": "FR-08", "name": "PulseHeberg (Paris)", "target": "178.32.0.1", "country": "🇫🇷 FR", "loc": "Париж"},
    {"id": "FR-09", "name": "Hosteur (Aix-en-Provence)", "target": "185.26.112.1", "country": "🇫🇷 FR", "loc": "Экс-ан-Прованс"},

    # === 6. ШВЕЙЦАРИЯ И АВСТРИЯ (CH / AT) — 8 узлов ===
    {"id": "CH-01", "name": "Infomaniak (Geneva)", "target": "185.125.25.1", "country": "🇨🇭 CH", "loc": "Женева"},
    {"id": "CH-02", "name": "Hostpoint (Zurich)", "target": "217.26.48.1", "country": "🇨🇭 CH", "loc": "Цюрих"},
    {"id": "CH-03", "name": "Exoscale (Zurich/Geneva)", "target": "159.100.240.1", "country": "🇨🇭 CH", "loc": "Цюрих"},
    {"id": "CH-04", "name": "Init7 (Winterthur)", "target": "77.109.128.1", "country": "🇨🇭 CH", "loc": "Винтертур"},
    {"id": "CH-05", "name": "Green.ch (Lupfig)", "target": "194.209.192.1", "country": "🇨🇭 CH", "loc": "Лупфиг"},
    {"id": "AT-01", "name": "EDIS Global (Vienna)", "target": "194.88.107.1", "country": "🇦🇹 AT", "loc": "Вена (Interxion)"},
    {"id": "AT-02", "name": "Anexia (Vienna/Klagenfurt)", "target": "194.182.160.1", "country": "🇦🇹 AT", "loc": "Вена"},
    {"id": "AT-03", "name": "Alwyzon (Vienna)", "target": "193.106.175.1", "country": "🇦🇹 AT", "loc": "Вена"},

    # === 7. ЛИТВА, ЛАТВИЯ, ЭСТОНИЯ (LT / LV / EE) — 8 узлов ===
    {"id": "LT-01", "name": "Time4VPS (Vilnius)", "target": "194.135.80.1", "country": "🇱🇹 LT", "loc": "Вильнюс"},
    {"id": "LT-02", "name": "Hostens (Vilnius)", "target": "185.170.114.1", "country": "🇱🇹 LT", "loc": "Вильнюс"},
    {"id": "LT-03", "name": "Cherry Servers (Siauliai)", "target": "84.32.188.1", "country": "🇱🇹 LT", "loc": "Шяуляй"},
    {"id": "LV-01", "name": "DEAC (Riga)", "target": "91.198.156.1", "country": "🇱🇻 LV", "loc": "Рига"},
    {"id": "LV-02", "name": "Nano.lv (Riga)", "target": "185.67.0.1", "country": "🇱🇻 LV", "loc": "Рига"},
    {"id": "LV-03", "name": "Serveris.lv (Riga)", "target": "87.110.128.1", "country": "🇱🇻 LV", "loc": "Рига"},
    {"id": "EE-01", "name": "Zone.ee (Tallinn)", "target": "217.146.64.1", "country": "🇪🇪 EE", "loc": "Таллин"},
    {"id": "EE-02", "name": "WaveCom (Tallinn)", "target": "80.79.112.1", "country": "🇪🇪 EE", "loc": "Таллин"},

    # === 8. ПОЛЬША, ЧЕХИЯ, СЛОВАКИЯ, ВЕНГРИЯ (PL / CZ / SK / HU) — 8 узлов ===
    {"id": "PL-01", "name": "OVHcloud (Warsaw)", "target": "51.68.136.1", "country": "🇵🇱 PL", "loc": "Варшава"},
    {"id": "PL-02", "name": "Atthost (Warsaw)", "target": "185.135.88.1", "country": "🇵🇱 PL", "loc": "Варшава"},
    {"id": "PL-03", "name": "Mikrus (Warsaw)", "target": "188.68.224.1", "country": "🇵🇱 PL", "loc": "Варшава"},
    {"id": "CZ-01", "name": "Wedos (Hluboka)", "target": "46.28.105.1", "country": "🇨🇿 CZ", "loc": "Глубока-над-Влтавоу"},
    {"id": "CZ-02", "name": "Vshosting (Prague)", "target": "89.185.224.1", "country": "🇨🇿 CZ", "loc": "Прага"},
    {"id": "CZ-03", "name": "Forpsi (Kdyně)", "target": "81.2.192.1", "country": "🇨🇿 CZ", "loc": "Кдыне"},
    {"id": "SK-01", "name": "Webglobe (Bratislava)", "target": "185.20.12.1", "country": "🇸🇰 SK", "loc": "Братислава"},
    {"id": "HU-01", "name": "ServerGarden (Budapest)", "target": "185.112.156.1", "country": "🇭🇺 HU", "loc": "Будапешт"},

    # === 9. ВЕЛИКОБРИТАНИЯ И ИРЛАНДИЯ (UK / IE) — 7 узлов ===
    {"id": "UK-01", "name": "Clouvider (London)", "target": "185.42.220.13", "country": "🇬🇧 UK", "loc": "Лондон"},
    {"id": "UK-02", "name": "Mythic Beasts (Cambridge)", "target": "93.93.128.1", "country": "🇬🇧 UK", "loc": "Кембридж / Лондон"},
    {"id": "UK-03", "name": "Krystal Hosting (London)", "target": "77.72.0.1", "country": "🇬🇧 UK", "loc": "Лондон"},
    {"id": "UK-04", "name": "20i Hosting (London)", "target": "185.151.28.1", "country": "🇬🇧 UK", "loc": "Лондон"},
    {"id": "UK-05", "name": "FastHosts (Gloucester)", "target": "213.171.192.1", "country": "🇬🇧 UK", "loc": "Глостер"},
    {"id": "UK-06", "name": "Bytemark (Manchester)", "target": "212.110.160.1", "country": "🇬🇧 UK", "loc": "Манчестер"},
    {"id": "IE-01", "name": "Blacknight (Carlow)", "target": "217.114.160.1", "country": "🇮🇪 IE", "loc": "Карлоу / Дублин"},

    # === 10. БОЛГАРИЯ, РУМЫНИЯ, МОЛДОВА, КИПР (BG / RO / MD / CY) — 8 узлов ===
    {"id": "BG-01", "name": "AlphaVPS (Sofia)", "target": "79.124.7.8", "country": "🇧🇬 BG", "loc": "София (Telepoint)"},
    {"id": "BG-02", "name": "SuperHosting (Sofia)", "target": "79.124.0.1", "country": "🇧🇬 BG", "loc": "София"},
    {"id": "MD-01", "name": "AlexHost (Chisinau)", "target": "176.123.0.1", "country": "🇲🇩 MD", "loc": "Кишинев"},
    {"id": "MD-02", "name": "PQ.Hosting (Chisinau)", "target": "194.26.229.1", "country": "🇲🇩 MD", "loc": "Кишинев"},
    {"id": "CY-01", "name": "MVPS.net (Larnaca)", "target": "185.112.248.1", "country": "🇨🇾 CY", "loc": "Ларнака"},
    {"id": "RO-01", "name": "Hosterion (Cluj-Napoca)", "target": "89.42.216.1", "country": "🇷🇴 RO", "loc": "Клуж-Напока"},
    {"id": "RO-02", "name": "Hostico (Oradea)", "target": "185.82.216.1", "country": "🇷🇴 RO", "loc": "Орадя"},
    {"id": "RO-03", "name": "Chocoping (Bucharest)", "target": "185.161.248.1", "country": "🇷🇴 RO", "loc": "Бухарест"},

    # === 11. ИСПАНИЯ, ИТАЛИЯ, ПОРТУГАЛИЯ (ES / IT / PT) — 6 узлов ===
    {"id": "ES-01", "name": "Arsys (Logrono)", "target": "82.98.128.1", "country": "🇪🇸 ES", "loc": "Логроньо / Мадрид"},
    {"id": "ES-02", "name": "CDmon (Barcelona)", "target": "212.36.192.1", "country": "🇪🇸 ES", "loc": "Барселона"},
    {"id": "IT-01", "name": "Aruba.it (Bergamo)", "target": "62.149.128.1", "country": "🇮🇹 IT", "loc": "Бергамо / Ареццо"},
    {"id": "IT-02", "name": "Seeweb (Milan)", "target": "217.61.0.1", "country": "🇮🇹 IT", "loc": "Милан"},
    {"id": "PT-01", "name": "PTisp (Lisbon)", "target": "185.15.20.1", "country": "🇵🇹 PT", "loc": "Лиссабон"},
    {"id": "PT-02", "name": "WebHS (Porto)", "target": "185.11.164.1", "country": "🇵🇹 PT", "loc": "Порту"},

    # === 12. США И КАНАДА (US / CA) — 12 узлов ===
    {"id": "US-01", "name": "Hetzner Ashburn (ASH)", "target": "5.161.7.195", "country": "🇺🇸 US", "loc": "Ашберн (Вирджиния)"},
    {"id": "US-02", "name": "Hetzner Hillsboro (HIL)", "target": "5.78.7.195", "country": "🇺🇸 US", "loc": "Хиллсборо (Орегон)"},
    {"id": "US-03", "name": "Linode / Akamai (Newark)", "target": "50.116.57.237", "country": "🇺🇸 US", "loc": "Ньюарк (NJ)"},
    {"id": "US-04", "name": "Vultr (New Jersey)", "target": "108.61.149.172", "country": "🇺🇸 US", "loc": "Нью-Джерси"},
    {"id": "US-05", "name": "DigitalOcean (NYC1)", "target": "162.243.16.1", "country": "🇺🇸 US", "loc": "Нью-Йорк"},
    {"id": "US-06", "name": "BuyVM (Las Vegas)", "target": "209.141.56.135", "country": "🇺🇸 US", "loc": "Лас-Вегас (NV)"},
    {"id": "US-07", "name": "RackNerd (Los Angeles)", "target": "192.3.1.1", "country": "🇺🇸 US", "loc": "Лос-Анджелес"},
    {"id": "US-08", "name": "RamNode (Seattle)", "target": "199.241.136.1", "country": "🇺🇸 US", "loc": "Сиэтл"},
    {"id": "US-09", "name": "IncogNET (Kansas)", "target": "23.137.255.1", "country": "🇺🇸 US", "loc": "Канзас-Сити"},
    {"id": "US-10", "name": "Spartan Host (Seattle)", "target": "104.223.12.1", "country": "🇺🇸 US", "loc": "Сиэтл"},
    {"id": "CA-01", "name": "OVHcloud Beauharnois (BHS)", "target": "198.27.64.1", "country": "🇨🇦 CA", "loc": "Богарнуа (Квебек)"},
    {"id": "CA-02", "name": "Servarica (Montreal)", "target": "162.251.60.1", "country": "🇨🇦 CA", "loc": "Монреаль"},

    # === 13. АЗИЯ И ОКЕАНИЯ (SG / JP / HK / AU) — 5 узлов ===
    {"id": "SG-01", "name": "DigitalOcean (Singapore)", "target": "128.199.200.1", "country": "🇸🇬 SG", "loc": "Сингапур"},
    {"id": "SG-02", "name": "Linode / Akamai (Singapore)", "target": "139.162.8.1", "country": "🇸🇬 SG", "loc": "Сингапур"},
    {"id": "JP-01", "name": "Sakura Internet (Tokyo)", "target": "160.16.0.1", "country": "🇯🇵 JP", "loc": "Токио"},
    {"id": "JP-02", "name": "Linode / Akamai (Tokyo2)", "target": "139.162.65.1", "country": "🇯🇵 JP", "loc": "Токио"},
    {"id": "AU-01", "name": "Vultr (Sydney)", "target": "108.61.212.1", "country": "🇦🇺 AU", "loc": "Сидней"},
]


def check_target(target: str) -> Dict[str, Any]:
    url = f"https://cheburcheck.ru/api/v1/check?target={target}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Accept": "application/json",
        },
    )
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait_time = 2.0 * (attempt + 1)
                time.sleep(wait_time)
                continue
            return {"error": f"HTTP {e.code}"}
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1.0)
                continue
            return {"error": str(e)}
    return {"error": "Timeout / Retries exhausted"}


def main():
    total = len(TARGETS)
    print("=" * 86)
    print(f"🚀 СТАРТ МАСШТАБНОГО АУДИТА: {total} ХОСТИНГОВ И ДЦ ЧЕРЕЗ CHEBURCHECK.RU")
    print("   Базы: Реестр РКН, antifilter.download, antifilter.network, 123jjck/cdn-ip-ranges")
    print("=" * 86)

    clean_list = []
    blocked_list = []
    error_list = []

    for idx, item in enumerate(TARGETS, 1):
        t = item["target"]
        name = item["name"]
        country = item["country"]
        loc = item["loc"]

        res = check_target(t)
        if "error" in res:
            status_str = f"⚠️ ОШИБКА ({res['error']})"
            error_list.append((item, res))
        else:
            is_blocked = res.get("blocked", False)
            geo = res.get("geo") or {}
            asn = geo.get("asn") or ""
            org = geo.get("organisation") or ""
            cdns = list(res.get("cdn_providers", {}).keys())
            cdns_str = f" [CDN: {','.join(cdns)}]" if cdns else ""

            if is_blocked:
                status_str = f"🔴 ЗАБЛОКИРОВАН{cdns_str}"
                blocked_list.append((item, res))
            else:
                status_str = f"🟢 ЧИСТЫЙ ({asn} {org[:20] if org else 'Unknown'})"
                clean_list.append((item, res))

        print(f"[{idx:03d}/{total:03d}] {country:8} | {name[:28]:28} | {t:15} -> {status_str}")
        # Задержка для соблюдения rate-limit (30-40 RPM)
        time.sleep(0.4)

    print("\n" + "=" * 86)
    print("📊 ИТОГИ АУДИТА 100 ХОСТИНГ-ПРОВАЙДЕРОВ:")
    print(f"  • Всего проверено:   {total}")
    print(f"  • 🟢 Чистые (НЕТ в реестрах РКН/CDN): {len(clean_list)} ({len(clean_list)/total*100:.1f}%)")
    print(f"  • 🔴 Заблокированы РКН/CDN:         {len(blocked_list)} ({len(blocked_list)/total*100:.1f}%)")
    print(f"  • ⚠️ Ошибки опроса API:              {len(error_list)}")
    print("=" * 86)

    # Генерация Markdown отчета
    report_path = "cheburcheck_100_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# 🛡 Аудит 100 мировых хостинг-провайдеров через Cheburcheck.ru\n\n")
        f.write(f"**Дата проверки:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"**Источники реестров:** Единый реестр РКН, `antifilter.network`, `antifilter.download`, `123jjck/cdn-ip-ranges`.\n\n")
        f.write("## 📊 Сводная статистика\n\n")
        f.write(f"- **Всего протестировано:** `{total}` узлов\n")
        f.write(f"- 🟢 **Чистые (доступны в РФ без блокировок):** `{len(clean_list)}` ({len(clean_list)/total*100:.1f}%)\n")
        f.write(f"- 🔴 **В черных списках РКН / CDN-блоках:** `{len(blocked_list)}` ({len(blocked_list)/total*100:.1f}%)\n\n")

        f.write("## 🟢 Топ лучших ЧИСТЫХ европейских и мировых хостингов (НЕТ в реестрах блокировок)\n\n")
        f.write("| Страна | Провайдер / ДЦ | IP-адрес | Локация | ASN | Организация |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for item, res in clean_list:
            geo = res.get("geo") or {}
            asn = geo.get("asn") or "-"
            org = geo.get("organisation") or "-"
            f.write(f"| {item['country']} | **{item['name']}** | `{item['target']}` | {item['loc']} | `{asn}` | {org} |\n")

        f.write("\n## 🔴 Заблокированные провайдеры (Попадают под фильтры РКН)\n\n")
        f.write("| Страна | Провайдер | IP-адрес | Причина / CDN |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        for item, res in blocked_list:
            cdns = list(res.get("cdn_providers", {}).keys())
            cdn_str = ", ".join(cdns) if cdns else "Черный список РКН / Antifilter"
            f.write(f"| {item['country']} | {item['name']} | `{item['target']}` | `{cdn_str}` |\n")

    print(f"\n📄 Полный отчет сохранен в файл: {report_path}")


if __name__ == "__main__":
    main()
