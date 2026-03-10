#!/usr/bin/env python3
"""
Multi-CDN Edge IP Scanner for Iran
Scans Cloudflare, Amazon CloudFront, and Fastly IP ranges
to find working edge IPs via HTTP/HTTPS testing

Version 2.0 - Multi-CDN Support
Author: @AghaFarokh
"""

import socket
import ssl
import time
import threading
import ipaddress
import json
import sys
import signal
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional

if sys.platform == 'win32':
    socket.setdefaulttimeout(5)


CDN_PROVIDERS = {
    "cloudflare": {
        "name": "Cloudflare",
        "subnets_file": "subnets_cloudflare.txt",
        "default_test_domain": "chatgpt.com",
        "default_subnets": [
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22",
        ],
    },
    "cloudfront": {
        "name": "Amazon CloudFront",
        "subnets_file": "subnets_cloudfront.txt",
        "default_test_domain": "aws.amazon.com",
        "default_subnets": [
            "3.160.0.0/11",
            "13.32.0.0/15",
            "13.35.0.0/16",
            "18.238.0.0/15",
            "52.46.0.0/18",
            "52.84.0.0/15",
            "54.182.0.0/16",
            "54.192.0.0/16",
            "54.230.0.0/16",
            "54.239.128.0/18",
            "64.252.64.0/18",
            "70.132.0.0/18",
            "99.84.0.0/16",
            "130.176.0.0/18",
            "204.246.164.0/22",
            "204.246.168.0/22",
            "205.251.192.0/19",
            "216.137.32.0/19",
        ],
    },
    "fastly": {
        "name": "Fastly",
        "subnets_file": "subnets_fastly.txt",
        "default_test_domain": "github.githubassets.com",
        "default_subnets": [
            "23.235.32.0/20",
            "43.249.72.0/22",
            "103.244.50.0/24",
            "103.245.222.0/23",
            "103.245.224.0/24",
            "104.156.80.0/20",
            "140.248.64.0/18",
            "140.248.128.0/17",
            "146.75.0.0/16",
            "151.101.0.0/16",
            "157.52.64.0/18",
            "167.82.0.0/17",
            "167.82.128.0/20",
            "167.82.160.0/20",
            "167.82.224.0/20",
            "172.111.64.0/18",
            "185.31.16.0/22",
            "199.27.72.0/21",
            "199.232.0.0/16",
        ],
    },
}


class CDNScanner:
    def __init__(self, config: Dict, cdn_provider: str = None):
        self.cdn_provider = (cdn_provider or config.get('cdn', 'cloudflare')).lower()
        if self.cdn_provider == 'all':
            self.cdn_provider = 'cloudflare'

        if self.cdn_provider not in CDN_PROVIDERS:
            print(f"Unknown CDN provider: '{self.cdn_provider}'. Defaulting to cloudflare.")
            self.cdn_provider = 'cloudflare'

        cdn_cfg = CDN_PROVIDERS[self.cdn_provider]
        self.cdn_name = cdn_cfg["name"]

        # Per-CDN domain overrides take priority, then global test_domain, then built-in default
        cdn_test_domains = config.get('cdn_test_domains', {})
        self.test_domain = (
            cdn_test_domains.get(self.cdn_provider)
            or config.get('test_domain')
            or cdn_cfg["default_test_domain"]
        )

        self.test_path = config.get('test_path', '/')
        self.timeout = config.get('timeout', 3)
        self.max_workers = config.get('max_workers', 100)
        self.test_download = config.get('test_download', True)
        self.download_size = config.get('download_size', 1024 * 100)
        self.port = config.get('port', 443)
        self.results = []
        self.lock = threading.Lock()
        self.tested_count = 0
        self.total_ips = 0
        self.output_file = config.get('output_file', f'working_ips_{self.cdn_provider}')
        self.stop_scan = False

        self.randomize = config.get('randomize', False)
        self.random_ips_per_range = min(255, max(1, config.get('random_ips_per_range', 10)))
        self.mix_ranges = config.get('mix_ranges', False)

    def save_ip_realtime(self, result: Dict):
        """Save a single working IP immediately to file"""
        txt_filename = f"{self.output_file}.txt"
        with open(txt_filename, 'a', encoding='utf-8') as f:
            f.write(f"{result['ip']}\n")

    def clear_output_file(self):
        """Clear the output file at the start of a new scan"""
        txt_filename = f"{self.output_file}.txt"
        with open(txt_filename, 'w', encoding='utf-8') as f:
            pass

    def test_ip_http(self, ip: str) -> Optional[Dict]:
        """Test a single IP via HTTPS with TLS SNI and HTTP GET"""
        try:
            start_time = time.time()

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            try:
                sock.connect((ip, self.port))
                ssl_sock = context.wrap_socket(sock, server_hostname=self.test_domain)

                request = (
                    f"GET {self.test_path} HTTP/1.1\r\n"
                    f"Host: {self.test_domain}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                ssl_sock.send(request.encode())

                response = b""
                downloaded = 0

                while True:
                    chunk = ssl_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    downloaded += len(chunk)
                    if self.test_download and downloaded >= self.download_size:
                        break

                ssl_sock.close()
                sock.close()

                end_time = time.time()
                latency = (end_time - start_time) * 1000

                if b"HTTP/" in response[:20]:
                    download_time = end_time - start_time
                    speed_kbps = (downloaded / 1024) / download_time if download_time > 0 else 0

                    return {
                        'ip': ip,
                        'latency_ms': round(latency, 2),
                        'speed_kbps': round(speed_kbps, 2),
                        'downloaded_bytes': downloaded,
                        'status': 'success',
                        'timestamp': datetime.now().isoformat(),
                    }
                return None

            except (socket.timeout, ssl.SSLError, Exception):
                return None
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        except Exception:
            return None

    def test_ip_fast(self, ip: str) -> Optional[Dict]:
        """Fast TCP connection + TLS handshake only test"""
        try:
            start_time = time.time()

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            try:
                sock.connect((ip, self.port))
                ssl_sock = context.wrap_socket(sock, server_hostname=self.test_domain)

                end_time = time.time()
                latency = (end_time - start_time) * 1000

                ssl_sock.close()
                sock.close()

                return {
                    'ip': ip,
                    'latency_ms': round(latency, 2),
                    'status': 'success',
                    'timestamp': datetime.now().isoformat(),
                }

            except Exception:
                return None
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        except Exception:
            return None

    def scan_ip(self, ip: str) -> Optional[Dict]:
        """Scan a single IP and return result if successful"""
        if self.stop_scan:
            return None

        result = self.test_ip_http(ip) if self.test_download else self.test_ip_fast(ip)

        with self.lock:
            self.tested_count += 1
            if self.tested_count % 100 == 0:
                print(
                    f"Progress: {self.tested_count}/{self.total_ips} tested, "
                    f"{len(self.results)} working IPs found"
                )

        if result:
            with self.lock:
                self.results.append(result)
                self.save_ip_realtime(result)
                speed_str = (
                    f" - Speed: {result.get('speed_kbps', 0):.2f} KB/s"
                    if 'speed_kbps' in result
                    else ""
                )
                print(f"✓ Found working IP: {result['ip']} - Latency: {result['latency_ms']}ms{speed_str}")

        return result

    def split_to_24_ranges(self, subnets: List[str]) -> List[ipaddress.IPv4Network]:
        """Convert all subnets to /24 ranges and remove duplicates"""
        ranges_24_set = set()

        for subnet in subnets:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                if network.prefixlen <= 24:
                    for subnet_24 in network.subnets(new_prefix=24):
                        ranges_24_set.add(subnet_24)
                else:
                    ranges_24_set.add(network)
            except ValueError as e:
                print(f"Error parsing subnet {subnet}: {e}")

        return list(ranges_24_set)

    def generate_ips_from_subnets(self, subnets: List[str]) -> List[str]:
        """Generate list of IPs from subnet ranges with optimization options"""
        all_ips = []

        print("Converting subnets to /24 ranges...")
        ranges_24 = self.split_to_24_ranges(subnets)

        expected_count = 0
        for subnet in subnets:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                expected_count += (
                    2 ** (24 - network.prefixlen) if network.prefixlen <= 24 else 1
                )
            except Exception:
                pass

        duplicates_removed = expected_count - len(ranges_24)
        suffix = f" ({duplicates_removed} duplicates removed)" if duplicates_removed > 0 else ""
        print(f"Total /24 ranges: {len(ranges_24)}{suffix}")

        if self.mix_ranges:
            print("Shuffling /24 ranges...")
            random.shuffle(ranges_24)

        for network in ranges_24:
            try:
                hosts = list(network.hosts())
                if self.randomize:
                    num_to_pick = min(self.random_ips_per_range, len(hosts))
                    ips = [str(ip) for ip in random.sample(hosts, num_to_pick)]
                else:
                    ips = [str(ip) for ip in hosts]
                all_ips.extend(ips)
            except ValueError as e:
                print(f"Error processing range {network}: {e}")

        if self.randomize:
            print(f"Randomize enabled: {self.random_ips_per_range} IPs per /24 range")
        if self.mix_ranges:
            print("Range mixing enabled")

        return all_ips

    def scan_subnets(self, subnets: List[str]) -> List[Dict]:
        """Scan multiple subnets concurrently"""
        print(f"\n{'='*60}")
        print(f"{self.cdn_name} Edge IP Scanner")
        print(f"{'='*60}")
        print(f"Test Domain: {self.test_domain}")
        print(f"Timeout: {self.timeout}s")
        print(f"Max Workers: {self.max_workers}")
        print(f"Port: {self.port}")
        print(f"Download Test: {self.test_download}")
        randomize_label = f" ({self.random_ips_per_range} IPs per /24)" if self.randomize else ""
        print(f"Randomize: {self.randomize}{randomize_label}")
        print(f"Mix Ranges: {self.mix_ranges}")
        print(f"{'='*60}\n")

        print("Generating IP list from subnets...")
        ip_list = self.generate_ips_from_subnets(subnets)
        self.total_ips = len(ip_list)

        if self.total_ips == 0:
            print("No IPs to scan!")
            return []

        print(f"Total IPs to scan: {self.total_ips}\n")

        self.clear_output_file()
        print(f"Saving working IPs to: {self.output_file}.txt (real-time)\n")

        start_time = time.time()

        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self.scan_ip, ip): ip for ip in ip_list}

                try:
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception:
                            pass
                except KeyboardInterrupt:
                    print("\n\n⚠ Scan interrupted by user! Stopping gracefully...")
                    self.stop_scan = True
                    for future in futures:
                        future.cancel()
                    executor.shutdown(wait=True, cancel_futures=True)
                    raise

        except KeyboardInterrupt:
            pass

        end_time = time.time()
        elapsed = end_time - start_time

        print(f"\n{'='*60}")
        print(f"Scan {'Interrupted' if self.stop_scan else 'Complete'}!")
        print(f"{'='*60}")
        print(f"Total IPs scanned: {self.tested_count}")
        print(f"Working IPs found: {len(self.results)}")
        print(f"Time elapsed: {elapsed:.2f}s")
        if elapsed > 0:
            print(f"Scan rate: {self.tested_count / elapsed:.2f} IPs/s")
        print(f"{'='*60}\n")

        self.results.sort(key=lambda x: x.get('latency_ms', float('inf')))
        return self.results

    def save_results(self, filename: str = None):
        """Save results to JSON file"""
        if filename is None:
            filename = f"{self.output_file}.json"

        output = {
            'scan_date': datetime.now().isoformat(),
            'cdn_provider': self.cdn_provider,
            'cdn_name': self.cdn_name,
            'test_domain': self.test_domain,
            'total_scanned': self.tested_count,
            'working_ips_count': len(self.results),
            'working_ips': self.results,
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"Results saved to {filename}")

        txt_filename = filename.replace('.json', '.txt')
        with open(txt_filename, 'w', encoding='utf-8') as f:
            for result in self.results:
                f.write(f"{result['ip']}\n")

        print(f"IP list saved to {txt_filename}")

    def print_top_ips(self, count: int = 10):
        """Print top working IPs sorted by latency"""
        if not self.results:
            print("No working IPs found!")
            return

        print(f"\nTop {min(count, len(self.results))} Working IPs ({self.cdn_name}):")
        print(f"{'='*80}")
        print(f"{'IP Address':<18} {'Latency':<12} {'Speed':<15} {'Status'}")
        print(f"{'-'*80}")

        for result in self.results[:count]:
            ip = result['ip']
            latency = f"{result['latency_ms']}ms"
            speed = f"{result.get('speed_kbps', 0):.2f} KB/s" if 'speed_kbps' in result else "N/A"
            print(f"{ip:<18} {latency:<12} {speed:<15} {result['status']}")

        print(f"{'='*80}\n")


# Backward-compatibility alias
CloudflareScanner = CDNScanner


def load_subnets_from_file(filename: str) -> List[str]:
    """Load subnets from a text file (one subnet per line)"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            subnets = [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith('#')
            ]
        if subnets:
            print(f"Loaded {len(subnets)} subnets from {filename}")
        return subnets
    except FileNotFoundError:
        return []


def load_subnets_for_cdn(cdn_provider: str, config: Dict) -> List[str]:
    """Load subnets for a specific CDN provider with fallback chain"""
    cdn_cfg = CDN_PROVIDERS[cdn_provider]

    # 1. Try CDN-specific subnets file
    subnets = load_subnets_from_file(cdn_cfg["subnets_file"])

    # 2. For cloudflare, also try legacy subnets.txt
    if not subnets and cdn_provider == 'cloudflare':
        subnets = load_subnets_from_file('subnets.txt')

    # 3. Fall back to built-in defaults
    if not subnets:
        subnets = cdn_cfg["default_subnets"]
        print(f"Using built-in default subnets for {cdn_cfg['name']}")

    return subnets


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    raise KeyboardInterrupt


def run_scan_for_cdn(cdn_provider: str, config: Dict, is_all_mode: bool = False) -> List[Dict]:
    """Run a complete scan for a specific CDN provider"""
    scan_config = config.copy()

    # In "all" mode, remove the global test_domain so each CDN uses its own default
    if is_all_mode:
        scan_config.pop('test_domain', None)
        scan_config.pop('output_file', None)

    scanner = CDNScanner(scan_config, cdn_provider=cdn_provider)
    subnets = load_subnets_for_cdn(cdn_provider, config)

    if not subnets:
        print(f"No subnets found for {CDN_PROVIDERS[cdn_provider]['name']}!")
        return []

    results = scanner.scan_subnets(subnets)
    scanner.print_top_ips(20)
    scanner.save_results()

    return results


def main():
    signal.signal(signal.SIGINT, signal_handler)

    try:
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
    except FileNotFoundError:
        print("config.json not found! Creating default configuration...")
        config = {
            'cdn': 'cloudflare',
            'cdn_test_domains': {
                'cloudflare': 'chatgpt.com',
                'cloudfront': 'aws.amazon.com',
                'fastly': 'github.githubassets.com',
            },
            'test_path': '/',
            'timeout': 3,
            'max_workers': 100,
            'test_download': True,
            'download_size': 102400,
            'port': 443,
            'randomize': False,
            'random_ips_per_range': 10,
            'mix_ranges': False,
        }
        with open('config.json', 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        print("Default config.json created. Please edit and run again.")
        return

    cdn = config.get('cdn', 'cloudflare').lower()

    if cdn == 'all':
        print("="*60)
        print("Scanning all CDN providers: Cloudflare, CloudFront, Fastly")
        print("="*60)
        all_results = {}
        for provider in CDN_PROVIDERS:
            print(f"\n{'#'*60}")
            print(f"# Starting scan for {CDN_PROVIDERS[provider]['name']}")
            print(f"{'#'*60}")
            try:
                results = run_scan_for_cdn(provider, config, is_all_mode=True)
                all_results[provider] = results
            except KeyboardInterrupt:
                print(f"\n⚠ Scan interrupted during {CDN_PROVIDERS[provider]['name']} scan!")
                break

        print(f"\n{'='*60}")
        print("All CDN Scans Summary:")
        print(f"{'='*60}")
        for provider, results in all_results.items():
            print(f"  {CDN_PROVIDERS[provider]['name']}: {len(results)} working IPs")
        print(f"{'='*60}")

    elif cdn in CDN_PROVIDERS:
        run_scan_for_cdn(cdn, config)

    else:
        valid = ', '.join(list(CDN_PROVIDERS.keys()) + ['all'])
        print(f"Unknown CDN provider: '{cdn}'")
        print(f"Valid options: {valid}")
        return

    print("\nScan completed successfully!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Scan interrupted by user!")
        print("✓ Working IPs found so far have been saved")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n✗ Error occurred: {e}")
        sys.exit(1)
