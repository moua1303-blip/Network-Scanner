#!/usr/bin/env python3
"""
Network Scanner - أداة مسح الشبكة
تسحب IPs النشطة من نطاق محدد وتحفظ النتائج في ملف txt.
"""

import ipaddress
import subprocess
import sys
import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from queue import Queue

# ألوان للطباعة (اختيارية)
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def print_banner():
    banner = f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════╗
║                    Network Scanner v1.0                             ║
║              اكتشاف الأجهزة النشطة في الشبكة                        ║
╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)

def ping_host(ip, timeout=2):
    """Ping host باستخدام أمر النظام، يعيد True إذا كان نشطاً."""
    # تحديد معامل ping حسب نظام التشغيل
    param = '-n' if sys.platform.lower().startswith('win') else '-c'
    command = ['ping', param, '1', '-w', str(timeout * 1000), str(ip)]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False

def tcp_scan(ip, ports, timeout=2):
    """مسح TCP لمنافذ محددة، يعيد True إذا كان أي منفذ مفتوح."""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return True
        except:
            pass
    return False

def check_host(ip, method='icmp', ports=None, timeout=2):
    """التحقق من نشاط الـ IP باستخدام الطريقة المحددة."""
    if method == 'icmp':
        return ping_host(ip, timeout)
    elif method == 'tcp' and ports:
        return tcp_scan(ip, ports, timeout)
    else:
        # افتراضي: icmp ثم tcp على 80,443 إذا فشل icmp
        if ping_host(ip, timeout):
            return True
        if ports:
            return tcp_scan(ip, ports, timeout)
        return False

def scan_network(network_cidr, method='icmp', ports=None, threads=50, timeout=2, verbose=False):
    """مسح كل الـ IPs في النطاق وإرجاع قائمة بالأجهزة النشطة."""
    network = ipaddress.ip_network(network_cidr, strict=False)
    hosts = list(network.hosts())
    total = len(hosts)
    active = []
    lock = threading.Lock()
    progress_queue = Queue()

    print(f"{Colors.YELLOW}[*] بدء المسح على {network_cidr} - {total} عنوان IP{Colors.RESET}")
    print(f"[*] الطريقة: {method.upper()}", end='')
    if ports:
        print(f" | المنافذ: {ports}")
    else:
        print()

    start_time = time.time()

    def worker(ip):
        if check_host(str(ip), method, ports, timeout):
            with lock:
                active.append(str(ip))
                if verbose:
                    print(f"{Colors.GREEN}[+] نشط: {ip}{Colors.RESET}")
        progress_queue.put(1)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, ip) for ip in hosts]
        # عرض شريط التقدم
        completed = 0
        while completed < total:
            try:
                progress_queue.get(timeout=1)
                completed += 1
                percent = (completed / total) * 100
                bar_length = 40
                filled = int(bar_length * completed // total)
                bar = '█' * filled + '░' * (bar_length - filled)
                sys.stdout.write(f"\r[%s] %d/%d (%.1f%%)" % (bar, completed, total, percent))
                sys.stdout.flush()
            except:
                pass
        print()  # سطر جديد بعد الشريط

    elapsed = time.time() - start_time
    print(f"{Colors.GREEN}[✓] اكتمل المسح في {elapsed:.2f} ثانية{Colors.RESET}")
    return active

def save_results(active_ips, output_file):
    """حفظ النتائج في ملف نصي مع معلومات إضافية."""
    with open(output_file, 'w') as f:
        f.write(f"# نتائج مسح الشبكة\n")
        f.write(f"# التاريخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# إجمالي الأجهزة النشطة: {len(active_ips)}\n\n")
        for ip in active_ips:
            f.write(f"{ip}\n")
    print(f"{Colors.GREEN}[✓] تم حفظ النتائج في {output_file}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description='أداة مسح الشبكة - اكتشاف الأجهزة النشطة')
    parser.add_argument('-n', '--network', required=True, help='النطاق بصيغة CIDR (مثال: 192.168.1.0/24)')
    parser.add_argument('-m', '--method', choices=['icmp', 'tcp'], default='icmp', help='طريقة المسح (icmp أو tcp)')
    parser.add_argument('-p', '--ports', help='منافذ TCP مفصولة بفواصل (مثال: 80,443,22)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='عدد الخيوط المتزامنة (الافتراضي: 50)')
    parser.add_argument('-to', '--timeout', type=int, default=2, help='مهلة الانتظار بالثواني (الافتراضي: 2)')
    parser.add_argument('-o', '--output', default='active_hosts.txt', help='ملف الإخراج (الافتراضي: active_hosts.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='عرض النتائج فور اكتشافها')
    parser.add_argument('--no-banner', action='store_true', help='عدم عرض الشعار')

    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    # معالجة المنافذ
    ports_list = None
    if args.ports:
        ports_list = [int(p.strip()) for p in args.ports.split(',')]

    # المسح
    active = scan_network(args.network, method=args.method, ports=ports_list,
                          threads=args.threads, timeout=args.timeout, verbose=args.verbose)

    # عرض النتائج النهائية
    if active:
        print(f"\n{Colors.GREEN}[+] الأجهزة النشطة ({len(active)}):{Colors.RESET}")
        for ip in active:
            print(f"    {ip}")
        save_results(active, args.output)
    else:
        print(f"{Colors.RED}[-] لم يتم العثور على أي جهاز نشط في النطاق {args.network}{Colors.RESET}")

if __name__ == '__main__':
    main()