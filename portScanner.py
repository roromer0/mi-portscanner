#!/usr/bin/env python3
"""
portscanner.py — escáner de puertos TCP en línea de comandos.

Uso responsable: solo escanea hosts sobre los que tengas permiso explícito
(tus propias máquinas, laboratorios de pentesting tipo HTB/TryHackMe, o
autorización escrita). Escanear sistemas de terceros sin permiso puede
constituir un delito.

Ejemplos:
    python3 portscanner.py 192.168.1.1
    python3 portscanner.py scanme.nmap.org -p 1-1000
    python3 portscanner.py 10.0.0.5 -p 22,80,443,3389 -b -v
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

CYAN = "\033[96m"
RESET = "\033[0m"

BANNER = r"""
   _________  _________  ____ ___  ___  _________
  / ___/ __ \/ ___/ __ \/ __ `__ \/ _ \/ ___/ __ \
 / /  / /_/ / /  / /_/ / / / / / /  __/ /  / /_/ /
/_/   \____/_/   \____/_/ /_/ /_/\___/_/   \____/

   ______________ _____  ____  ___  _____
  / ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 (__  ) /__/ /_/ / / / / / / /  __/ /
/____/\___/\__,_/_/ /_/_/ /_/\___/_/
                    TCP Port Scanner
"""


def print_banner():
    print(f"{CYAN}{BANNER}{RESET}")


# Puertos comunes por defecto si el usuario no especifica un rango
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                  445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Nombres de servicio conocidos para dar contexto (orientativo, no autoritativo)
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-alt",
}


def parse_ports(port_spec):
    """Convierte '22,80,443' o '1-1000' o una mezcla en una lista ordenada de ints."""
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def grab_banner(sock):
    """Intenta leer un banner del servicio tras conectar (best-effort)."""
    try:
        sock.settimeout(1.0)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner.splitlines()[0] if banner else ""
    except Exception:
        return ""


def scan_port(target_ip, port, timeout, grab_banners):
    """Intenta un TCP connect al puerto. Devuelve (port, is_open, banner)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                banner = grab_banner(sock) if grab_banners else ""
                return port, True, banner
            return port, False, ""
    except socket.error:
        return port, False, ""


def main():
    parser = argparse.ArgumentParser(
        description="Escáner de puertos TCP simple (TCP connect scan).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Solo usa esta herramienta contra sistemas donde tengas permiso explícito.",
    )
    parser.add_argument("target", help="IP o hostname objetivo")
    parser.add_argument("-p", "--ports", default=None,
                         help="Puertos a escanear, ej: '80', '1-1000', '22,80,443'. "
                              "Por defecto escanea una lista de puertos comunes.")
    parser.add_argument("-t", "--threads", type=int, default=100,
                         help="Número de hilos concurrentes (por defecto: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Timeout de conexión en segundos (por defecto: 1.0)")
    parser.add_argument("-b", "--banner", action="store_true",
                         help="Intentar capturar el banner del servicio en puertos abiertos")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Mostrar también los puertos cerrados/filtrados")
    args = parser.parse_args()

    print_banner()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] No se pudo resolver el host: {args.target}")
        sys.exit(1)

    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS

    print(f"\nEscaneando {args.target} ({target_ip})")
    print(f"Puertos: {len(ports)} | Hilos: {args.threads} | Timeout: {args.timeout}s\n")

    start = time.time()
    open_ports = []

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(scan_port, target_ip, port, args.timeout, args.banner): port
                for port in ports
            }
            for future in as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    open_ports.append((port, banner))
                elif args.verbose:
                    print(f"  {port:>5}/tcp  cerrado/filtrado")
    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario.")
        sys.exit(1)

    elapsed = time.time() - start

    print(f"\n{'PUERTO':<10}{'ESTADO':<10}{'SERVICIO':<15}{'BANNER'}")
    print("-" * 60)
    for port, banner in sorted(open_ports):
        service = COMMON_SERVICES.get(port, "?")
        print(f"{port:<10}{'abierto':<10}{service:<15}{banner}")

    if not open_ports:
        print("No se encontraron puertos abiertos.")

    print(f"\nEscaneo completado en {elapsed:.2f} segundos. "
          f"{len(open_ports)} puerto(s) abierto(s) de {len(ports)} analizados.")


if __name__ == "__main__":
    main()