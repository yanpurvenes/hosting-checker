#!/usr/bin/env python3
"""
trace_hosting.py - Трассировка и проверка блокировок РКН к Infomaniak и
зарубежным хостингам по фиксированным IP-адресам из базы проверок (hosting-checker).

Особенности:
  - ПРИВАТНОСТЬ: Актуальный IP пользователя НЕ запрашивается и НЕ выводится.
    Локальные адреса шлюза/сети маскируются.
  - ТАРГЕТИНГ: Проверки и трассировка выполняются напрямую по фиксированным IP
    дата-центров хостингов (как в hosting_checker), исключая влияние DNS.
  - ДИАГНОСТИКА:
      1. TCP 443 / 80 Ping (замер RTT и выявление TCP RST / Drop ТСПУ).
      2. TLS SNI Handshake к целевому IP (выявление DPI блокировки по SNI).
      3. HTTP статус и проверка на заглушки провайдеров.
      4. Пошаговая трассировка маршрута (traceroute / TCP traceroute) в реальном времени.
      5. BGP/ASN обогащение промежуточных транзитных узлов.
"""

import argparse
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

# Цветовое оформление ANSI
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_CYAN = "\033[96m"
C_DIM = "\033[90m"

# Маркеры ISP/РКН заглушек
STUB_KEYWORDS = (
    "доступ ограничен",
    "доступ к запрашиваемому ресурсу",
    "роскомнадзор",
    "решению суда",
    "заблокирован",
    "blocked by roskomnadzor",
    "blocked by rkn",
    "rkn.gov.ru",
    "eais.rkn.gov.ru",
    "единый реестр",
    "запрещен",
)

# Каталог хостинг-провайдеров с фиксированными IP (соответствует базе hosting_checker)
HOSTING_TARGETS = {
    "infomaniak": {
        "id": "CH.INF-01",
        "name": "Infomaniak Network",
        "country": "CH 🇨🇭",
        "host": "www.infomaniak.com",
        "ip": "185.125.25.1",
        "asn": "AS29222 (Infomaniak Network SA)",
        "desc": "Швейцарский хостинг и облачная инфраструктура (Женева)",
    },
    "hetzner": {
        "id": "DE.HE-01",
        "name": "Hetzner (Германия)",
        "country": "DE 🇩🇪",
        "host": "king.hr",
        "ip": "144.76.4.228",
        "asn": "AS24940 (Hetzner Online GmbH)",
        "desc": "Дата-центр Hetzner в Германии (Фалькенштайн / Нюрнберг)",
    },
    "hetzner_fi": {
        "id": "FI.HE-01",
        "name": "Hetzner (Финляндия)",
        "country": "FI 🇫🇮",
        "host": "nioges.com",
        "ip": "95.216.4.218",
        "asn": "AS24940 (Hetzner Online GmbH)",
        "desc": "Дата-центр Hetzner в Хельсинки (Финляндия)",
    },
    "ovh": {
        "id": "FR.OVH-01",
        "name": "OVHcloud",
        "country": "FR 🇫🇷",
        "host": "www.adwin.fr",
        "ip": "188.165.254.16",
        "asn": "AS16276 (OVH SAS)",
        "desc": "Европейский дата-центр OVH в Рубе / Гравелине (Франция)",
    },
    "digitalocean": {
        "id": "DE.DO-01",
        "name": "DigitalOcean",
        "country": "EU 🇪🇺",
        "host": "ui-arts.com",
        "ip": "139.59.129.242",
        "asn": "AS14061 (DigitalOcean)",
        "desc": "Облачный узел DigitalOcean (Европа / Франкфурт)",
    },
    "aws": {
        "id": "DE.AWS-01",
        "name": "Amazon Web Services (AWS)",
        "country": "DE 🇩🇪",
        "host": "amplifon.com",
        "ip": "18.198.63.243",
        "asn": "AS16509 (Amazon.com)",
        "desc": "AWS Cloud регион eu-central-1 (Франкфурт)",
    },
    "cloudflare": {
        "id": "US.CF-02",
        "name": "Cloudflare CDN",
        "country": "Global 🌐",
        "host": "esm.sh",
        "ip": "172.67.70.222",
        "asn": "AS13335 (Cloudflare)",
        "desc": "Глобальный Anycast CDN провайдер",
    },
    "vultr": {
        "id": "DE.VLTR-01",
        "name": "Vultr",
        "country": "DE 🇩🇪",
        "host": "askit-app.de",
        "ip": "192.248.182.205",
        "asn": "AS20473 (Choopa / Vultr)",
        "desc": "Дата-центр Vultr (Франкфурт)",
    },
    "netcup": {
        "id": "DE.NCP-01",
        "name": "Netcup",
        "country": "DE 🇩🇪",
        "host": "www.netcup.de",
        "ip": "46.38.224.30",
        "asn": "AS197540 (netcup GmbH)",
        "desc": "Немецкий VPS / root-сервер хостинг",
    },
    "contabo": {
        "id": "FR.CNTB-01",
        "name": "Contabo",
        "country": "DE/FR 🇪🇺",
        "host": "antoniotartaglia.it",
        "ip": "13.140.169.107",
        "asn": "AS51167 (Contabo GmbH)",
        "desc": "Дата-центр Contabo",
    },
}

# Кэш BGP/ASN информации
AS_CACHE: Dict[str, Tuple[str, str, str]] = {}


def check_vpn_tunnel() -> Optional[str]:
    """
    Проверяет, активен ли VPN/TUN интерфейс (utun, tun, wg),
    БЕЗ запроса и вывода внешнего IP пользователя.
    """
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=2).stdout
            m = re.search(r"default\s+\S+\s+\S+\s+(\w+)", out)
            if m:
                iface = m.group(1)
                if any(iface.startswith(p) for p in ("utun", "tun", "ppp")):
                    return iface
        elif sys.platform.startswith("linux"):
            out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=2).stdout
            m = re.search(r"dev\s+(\w+)", out)
            if m:
                iface = m.group(1)
                if any(iface.startswith(p) for p in ("tun", "utun", "wg")):
                    return iface
    except Exception:
        pass
    return None


def mask_client_ip(ip: str) -> str:
    """Маскирует приватные и клиентские локальные IP адреса для анонимности."""
    if not ip or ip == "*":
        return "* * *"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            parts = ip.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.*.*"
            return "LAN-PRIVATE"
    except ValueError:
        pass
    return ip


def get_ip_as_info(ip: str) -> Tuple[str, str, str]:
    """Получает BGP информацию (ASN, Название организации, Страна) для промежуточного узла."""
    if not ip or ip == "*":
        return ("", "", "")

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return ("", "Локальный шлюз / LAN", "LAN")
    except ValueError:
        return ("", "", "")

    if ip in AS_CACHE:
        return AS_CACHE[ip]

    # Запрос BGP метаданных транзитного IP
    try:
        url = f"http://ip-api.com/json/{ip}?fields=as,asname,org,countryCode"
        req = urllib.request.Request(url, headers={"User-Agent": "trace-hosting/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            asn_full = data.get("as", "")
            m = re.match(r"(AS\d+)\s*(.*)", asn_full)
            if m:
                asn = m.group(1)
                org = m.group(2) or data.get("org", data.get("asname", ""))
            else:
                asn = data.get("asname", "")
                org = data.get("org", "")
            cc = data.get("countryCode", "??")
            info = (asn, org, cc)
            AS_CACHE[ip] = info
            return info
    except Exception:
        AS_CACHE[ip] = ("", "", "")
        return ("", "", "")


def check_l4_l7_direct(target_ip: str, host_header: str) -> Dict[str, any]:
    """
    Проверяет доступность узла напрямую по IP-адресу без зависимости от системного DNS.
    Тестирует:
      - TCP SYN Connect (порты 443 и 80)
      - TLS SNI Handshake с передачей SNI
      - HTTP статус и проверка на маркеры блокировок
    """
    res = {
        "ip": target_ip,
        "tcp_443": False,
        "tcp_443_rtt": None,
        "tcp_80": False,
        "tcp_80_rtt": None,
        "tls_ok": False,
        "tls_rtt": None,
        "tls_error": None,
        "http_code": None,
        "http_stub": False,
        "error_msg": "",
    }

    # 1. TCP Connect (Port 443 и 80) напрямую к target_ip
    for port in (443, 80):
        t0 = time.monotonic()
        try:
            with socket.create_connection((target_ip, port), timeout=3.5):
                elapsed = (time.monotonic() - t0) * 1000
                if port == 443:
                    res["tcp_443"] = True
                    res["tcp_443_rtt"] = elapsed
                else:
                    res["tcp_80"] = True
                    res["tcp_80_rtt"] = elapsed
        except Exception as e:
            if port == 443:
                res["error_msg"] = str(e)

    # 2. TLS Handshake с SNI к целевому IP
    if res["tcp_443"]:
        t0 = time.monotonic()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target_ip, 443), timeout=3.5) as s:
                with ctx.wrap_socket(s, server_hostname=host_header) as ssock:
                    res["tls_ok"] = True
                    res["tls_rtt"] = (time.monotonic() - t0) * 1000
        except Exception as e:
            res["tls_error"] = str(e)

    # 3. HTTP запрос напрямую с Host заголовком
    if res["tcp_443"]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            url = f"https://{target_ip}/"
            req = urllib.request.Request(
                url,
                headers={
                    "Host": host_header,
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
            )
            with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
                res["http_code"] = resp.getcode()
                body = resp.read(4096).decode("utf-8", errors="ignore").lower()
                for kw in STUB_KEYWORDS:
                    if kw in body:
                        res["http_stub"] = True
                        break
        except urllib.error.HTTPError as e:
            res["http_code"] = e.code
        except Exception:
            pass

    return res


def parse_traceroute_line(line: str) -> Optional[Tuple[int, Optional[str], Optional[float]]]:
    """Парсит строку вывода traceroute. Возвращает (hop_num, ip, rtt_ms)."""
    line = line.strip()
    if not line or line.startswith("traceroute"):
        return None

    m = re.match(r"^(\d+)\s+(.+)$", line)
    if not m:
        return None

    hop_num = int(m.group(1))
    rest = m.group(2).strip()

    if rest == "*" or rest.startswith("* *"):
        return (hop_num, None, None)

    ip_match = re.search(r"\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?", rest)
    ip = ip_match.group(1) if ip_match else None

    rtt_match = re.search(r"(\d+(?:\.\d+)?)\s*ms", rest)
    rtt = float(rtt_match.group(1)) if rtt_match else None

    return (hop_num, ip, rtt)


def run_traceroute_streaming(
    target_ip: str,
    target_host: str,
    max_hops: int = 20,
    timeout_sec: int = 1,
    use_tcp: bool = False,
    port: int = 443,
) -> List[Dict[str, any]]:
    """
    Запускает traceroute напрямую на target_ip в потоковом режиме,
    выводя каждый хоп в реальном времени с маскировкой локальных IP.
    """
    print(f"\n{C_BOLD}{C_CYAN}>>> Пошаговая трассировка маршрута к {target_ip} ({target_host}){C_RESET}")
    if use_tcp:
        print(f"{C_DIM}    Режим: TCP SYN на порт {port} (L4){C_RESET}")
    else:
        print(f"{C_DIM}    Режим: Стандартный UDP (порты 33434+){C_RESET}")

    cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout_sec), "-q", "1"]
    if use_tcp:
        cmd.extend(["-P", "tcp", "-p", str(port)])
    cmd.append(target_ip)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        print(f"{C_RED}[!] Ошибка запуска traceroute: {e}{C_RESET}")
        return []

    print("-" * 86)
    print(f"{'#':>3}  {'IP / Узел':<28}  {'RTT':<9}  {'ASN / Организация':<32}  {'Страна'}")
    print("-" * 86)

    hops = []
    for line in proc.stdout:
        parsed = parse_traceroute_line(line)
        if not parsed:
            continue

        hop_num, ip, rtt = parsed
        hop_data = {
            "hop": hop_num,
            "ip": ip,
            "rtt": rtt,
            "asn": "",
            "org": "",
            "cc": "",
            "timeout": ip is None,
        }

        if ip:
            asn, org, cc = get_ip_as_info(ip)
            hop_data["asn"] = asn
            hop_data["org"] = org
            hop_data["cc"] = cc

            display_ip = mask_client_ip(ip) if hop_num <= 2 else ip
            rtt_display = f"{rtt:.1f} ms" if rtt is not None else "-"
            as_display = f"[{asn}] {org}" if asn else (org or "-")
            if len(as_display) > 31:
                as_display = as_display[:29] + ".."

            if ip == target_ip:
                print(
                    f"{hop_num:>3}  {C_GREEN}{display_ip:<28}{C_RESET}  "
                    f"{C_GREEN}{rtt_display:<9}{C_RESET}  "
                    f"{C_GREEN}{as_display:<32}{C_RESET}  "
                    f"{C_BOLD}{C_GREEN}{cc} [ЦЕЛЬ]{C_RESET}"
                )
            else:
                cc_color = C_GREEN if cc in ("CH", "DE", "FR", "FI", "NL", "GB", "US") else C_YELLOW
                print(f"{hop_num:>3}  {display_ip:<28}  {C_GREEN}{rtt_display:<9}{C_RESET}  {as_display:<32}  {cc_color}{cc}{C_RESET}")
        else:
            print(f"{hop_num:>3}  {C_DIM}* * * (тайм-аут / узел скрыт){C_RESET}")

        sys.stdout.flush()
        hops.append(hop_data)

    proc.wait()
    print("-" * 86)
    return hops


def analyze_route(hops: List[Dict[str, any]], target_name: str, target_ip: str, l4: Dict[str, any], ran_trace: bool):
    """Выводит детальный вердикт доступности хостинга и анализ возможных блокировок."""
    print(f"\n{C_BOLD}📊 Диагностика доступности [{target_name}] ({target_ip}):{C_RESET}")

    # 1. Анализ L4/L7
    if l4["tcp_443"] and l4["tls_ok"]:
        rtt_val = l4["tcp_443_rtt"]
        print(f"  {C_GREEN}✓ TCP (443) и TLS Handshake успешно пройдены!{C_RESET} (RTT: {rtt_val:.1f} ms)")
    elif l4["tcp_443"] and not l4["tls_ok"]:
        print(f"  {C_RED}✗ LIKELY TLS DPI FILTERING (Блокировка по SNI):{C_RESET}")
        print(f"    TCP соединение на порт 443 установлено, но TLS сброшен ({l4['tls_error']}).")
        print(f"    {C_YELLOW}→ Признак ТСПУ (фильтрация TLS ClientHello с именем хоста).{C_RESET}")
    elif not l4["tcp_443"]:
        print(f"  {C_RED}✗ TCP PORT 443 DROP / RESET (Порт недоступен):{C_RESET}")
        print(f"    Не удается установить соединение ({l4['error_msg']}).")
        print(f"    {C_YELLOW}→ Признак блокировки подсети/IP на ТСПУ или операторе.{C_RESET}")

    if l4["http_stub"]:
        print(f"  {C_RED}✗ ОБНАРУЖЕНА ЗАГЛУШКА ПРОВАЙДЕРА/РКН!{C_RESET}")

    # 2. Анализ Traceroute (если выполнялся)
    if not ran_trace:
        return

    valid_hops = [h for h in hops if not h["timeout"]]
    if not valid_hops:
        print(f"\n  {C_YELLOW}ℹ Промежуточные узлы не ответили на traceroute (все хопы * * *).{C_RESET}")
        print("    Это типично для VPN-туннелей или провайдеров, блокирующих ICMP Time Exceeded.")
        return

    last_hop = valid_hops[-1]
    last_ip = last_hop["ip"]
    last_as = last_hop["asn"]
    last_org = last_hop["org"]
    last_cc = last_hop["cc"]

    if last_ip == target_ip:
        print(f"  {C_GREEN}✓ Маршрут полностью пройден до целевого IP ({target_ip}) в {last_cc}!{C_RESET}")
    else:
        print(f"\n  {C_YELLOW}⚠ Маршрут оборвался на хопе #{last_hop['hop']}: {last_ip} [{last_as} {last_org}] ({last_cc}){C_RESET}")
        if last_cc == "RU":
            print(f"    {C_RED}→ Пакеты остановлены внутри РФ (на узле [{last_org}]).{C_RESET}")
            print("      Высокая вероятность IP-блокировки на ТСПУ (РКН) / фильтрации оператором.")
        else:
            print(f"    {C_BLUE}→ Пакеты вышли из РФ (последний ответ из {last_cc}).{C_RESET}")
            print("      Обрыв дальше может быть обусловлен фильтрацией ICMP дата-центром хостинга.")


def run_single_target(key: str, use_tcp: bool = False, max_hops: int = 20, no_trace: bool = False):
    """Запускает аудит для одного хостинга."""
    target = HOSTING_TARGETS[key]
    host = target["host"]
    ip = target["ip"]

    print("=" * 86)
    print(f"{C_BOLD}{C_GREEN} ПРОВЕРКА: {target['name']} ({target['country']}){C_RESET}")
    print(f" Целевой IP: {C_BOLD}{ip}{C_RESET} | Хост: {host} | {target['asn']}")
    print(f" Описание: {target['desc']}")
    print("=" * 86)

    # 1. Экспресс-тест L4/L7 напрямую на target_ip
    print(f"\n{C_DIM}[1/2] Проверка L4/L7 (TCP 443/80, TLS SNI, HTTP)...{C_RESET}")
    l4 = check_l4_l7_direct(ip, host)

    rtt_tcp = f"{l4['tcp_443_rtt']:.1f} ms" if l4["tcp_443_rtt"] else "TIMEOUT"
    tcp_status = f"{C_GREEN}OK ({rtt_tcp}){C_RESET}" if l4["tcp_443"] else f"{C_RED}DROP/RESET{C_RESET}"
    tls_status = f"{C_GREEN}OK ({l4['tls_rtt']:.1f} ms){C_RESET}" if l4["tls_ok"] else f"{C_RED}FAILED ({l4['tls_error']}){C_RESET}"
    http_status = f"{C_GREEN}HTTP {l4['http_code']}{C_RESET}" if l4["http_code"] and not l4["http_stub"] else (f"{C_RED}STUB DETECTED{C_RESET}" if l4["http_stub"] else "-")

    print(f"  • TCP (443): {tcp_status}")
    print(f"  • TLS (SNI): {tls_status}")
    print(f"  • HTTP:      {http_status}")

    # 2. Трассировка напрямую к IP
    if not no_trace:
        print(f"\n{C_DIM}[2/2] Трассировка маршрута к IP {ip}...{C_RESET}")
        hops = run_traceroute_streaming(ip, host, max_hops=max_hops, use_tcp=use_tcp)
        analyze_route(hops, target["name"], ip, l4, ran_trace=True)
    else:
        analyze_route([], target["name"], ip, l4, ran_trace=False)


def main():
    parser = argparse.ArgumentParser(
        description="Трассировка и проверка блокировок РКН к Infomaniak и зарубежным хостингам по фиксированным IP"
    )
    parser.add_argument("target", nargs="?", help="Имя провайдера (infomaniak, hetzner, ovh, digitalocean, aws, cf, all)")
    parser.add_argument("--tcp", action="store_true", help="Использовать TCP SYN трассировку (порт 443)")
    parser.add_argument("--max-hops", type=int, default=20, help="Максимальное количество хопов (по умолчанию 20)")
    parser.add_argument("--no-trace", action="store_true", help="Только экспресс-тест L4/L7 без выполнения traceroute")
    parser.add_argument("--all", action="store_true", help="Проверить все хостинги по очереди")

    args = parser.parse_args()

    # Проверка VPN без запроса/вывода пользовательского IP
    vpn_iface = check_vpn_tunnel()

    print("=" * 86)
    print(f"{C_BOLD}{C_CYAN}    ТРАССИРОВКА ХОСТИНГОВ И ДИАГНОСТИКА БЛОКИРОВОК РКН{C_RESET}")
    print(f"    База IP: Infomaniak, Hetzner, OVH, DigitalOcean, AWS, Cloudflare & more")
    print("=" * 86)
    if vpn_iface:
        print(f"{C_BOLD}{C_YELLOW} ⚠️  АКТИВЕН VPN-ТУННЕЛЬ ({vpn_iface}){C_RESET}")
        print(f"    Трафик идет через туннель, в обход ТСПУ/РКН и локального провайдера РФ.")
        print(f"    Для тестирования реальных блокировок на вашей линии отключите VPN перед запуском.")
        print("-" * 86)

    target_arg = (args.target or "").lower()

    if args.all or target_arg == "all":
        print(f"\n{C_BOLD}>>> Запуск аудита по всем {len(HOSTING_TARGETS)} хостингам...{C_RESET}\n")
        for key in HOSTING_TARGETS:
            run_single_target(key, use_tcp=args.tcp, max_hops=args.max_hops, no_trace=args.no_trace)
            print("\n")
        return

    if target_arg in HOSTING_TARGETS:
        run_single_target(target_arg, use_tcp=args.tcp, max_hops=args.max_hops, no_trace=args.no_trace)
        return

    # Интерактивное меню
    print(f"\n{C_BOLD}Выберите хостинг-провайдера:{C_RESET}\n")
    keys = list(HOSTING_TARGETS.keys())
    for idx, key in enumerate(keys, 1):
        t = HOSTING_TARGETS[key]
        print(f"  {C_CYAN}{idx:2d}.{C_RESET} {t['name']:<24} {t['country']:<10} {C_BOLD}{t['ip']:<16}{C_RESET} {C_DIM}— {t['desc']}{C_RESET}")

    print(f"  {C_CYAN}{len(keys)+1:2d}.{C_RESET} {'[Все хостинги подряд]':<24} 🌐")
    print(f"  {C_CYAN} 0.{C_RESET} Выход")

    try:
        choice = input(f"\n{C_BOLD}Введите номер (1-{len(keys)+1}, Enter=1 для Infomaniak): {C_RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nОтменено.")
        return

    if choice == "" or choice == "1":
        run_single_target("infomaniak", use_tcp=args.tcp, max_hops=args.max_hops, no_trace=args.no_trace)
    elif choice == "0":
        return
    elif choice.isdigit():
        num = int(choice)
        if 1 <= num <= len(keys):
            run_single_target(keys[num - 1], use_tcp=args.tcp, max_hops=args.max_hops, no_trace=args.no_trace)
        elif num == len(keys) + 1:
            for key in HOSTING_TARGETS:
                run_single_target(key, use_tcp=args.tcp, max_hops=args.max_hops, no_trace=args.no_trace)
                print("\n")
    else:
        if choice in HOSTING_TARGETS:
            run_single_target(choice, use_tcp=args.tcp, max_hops=args.max_hops, no_trace=args.no_trace)


if __name__ == "__main__":
    main()
