#!/usr/bin/env python3
"""
Cloudflare Edge IP Scanner for Iran
Scans Cloudflare IP ranges to find working edge IPs via HTTP/HTTPS testing
Custom built for Iran internet restrictions (Dey 1404) by @AghaFarokh
Author: @AghaFarokh

"""

import socket
import ssl
import time
import threading
import ipaddress
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import urllib.request
import urllib.error


class CloudflareScanner:
    def __init__(self, config: Dict):
        self.test_domain = config.get('test_domain', 'chatgpt.com')
        self.test_path = config.get('test_path', '/')
        self.timeout = config.get('timeout', 3)
        self.max_workers = config.get('max_workers', 100)
        self.test_download = config.get('test_download', True)
        self.download_size = config.get('download_size', 1024 * 100)  # 100KB
        self.port = config.get('port', 443)
        self.results = []
        self.lock = threading.Lock()
        self.tested_count = 0
        self.total_ips = 0

    def test_ip_http(self, ip: str) -> Optional[Dict]:
        """Test a single IP via HTTP/HTTPS with TLS SNI"""
        try:
            start_time = time.time()

            # Create SSL context with SNI support
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Create socket and connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            try:
                sock.connect((ip, self.port))

                # Wrap with SSL and specify SNI hostname
                ssl_sock = context.wrap_socket(sock, server_hostname=self.test_domain)

                # Send HTTP GET request
                request = f"GET {self.test_path} HTTP/1.1\r\nHost: {self.test_domain}\r\nConnection: close\r\n\r\n"
                ssl_sock.send(request.encode())

                # Receive response
                response = b""
                downloaded = 0

                while True:
                    chunk = ssl_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    downloaded += len(chunk)

                    # Stop after downloading test size
                    if self.test_download and downloaded >= self.download_size:
                        break

                ssl_sock.close()
                sock.close()

                end_time = time.time()
                latency = (end_time - start_time) * 1000  # Convert to ms

                # Check if response is valid HTTP
                if b"HTTP/" in response[:20]:
                    # Calculate download speed
                    download_time = end_time - start_time
                    speed_kbps = (downloaded / 1024) / download_time if download_time > 0 else 0

                    return {
                        'ip': ip,
                        'latency_ms': round(latency, 2),
                        'speed_kbps': round(speed_kbps, 2),
                        'downloaded_bytes': downloaded,
                        'status': 'success',
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    return None

            except socket.timeout:
                return None
            except ssl.SSLError as e:
                return None
            except Exception as e:
                return None
            finally:
                try:
                    sock.close()
                except:
                    pass

        except Exception as e:
            return None

    def test_ip_fast(self, ip: str) -> Optional[Dict]:
        """Fast TCP connection test with TLS handshake"""
        try:
            start_time = time.time()

            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            try:
                # Connect
                sock.connect((ip, self.port))

                # TLS handshake with SNI
                ssl_sock = context.wrap_socket(sock, server_hostname=self.test_domain)

                end_time = time.time()
                latency = (end_time - start_time) * 1000

                ssl_sock.close()
                sock.close()

                return {
                    'ip': ip,
                    'latency_ms': round(latency, 2),
                    'status': 'success',
                    'timestamp': datetime.now().isoformat()
                }

            except Exception as e:
                return None
            finally:
                try:
                    sock.close()
                except:
                    pass

        except Exception as e:
            return None

    def scan_ip(self, ip: str) -> Optional[Dict]:
        """Scan a single IP and return result if successful"""
        # Use full HTTP test if download testing is enabled
        if self.test_download:
            result = self.test_ip_http(ip)
        else:
            result = self.test_ip_fast(ip)

        with self.lock:
            self.tested_count += 1
            if self.tested_count % 100 == 0:
                print(f"Progress: {self.tested_count}/{self.total_ips} tested, {len(self.results)} working IPs found")

        if result:
            with self.lock:
                self.results.append(result)
                print(f"✓ Found working IP: {result['ip']} - Latency: {result['latency_ms']}ms" +
                      (f" - Speed: {result.get('speed_kbps', 0):.2f} KB/s" if 'speed_kbps' in result else ""))

        return result

    def generate_ips_from_subnets(self, subnets: List[str]) -> List[str]:
        """Generate list of IPs from subnet ranges"""
        all_ips = []

        for subnet in subnets:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                # Convert to list of IP strings
                ips = [str(ip) for ip in network.hosts()]
                all_ips.extend(ips)
                print(f"Loaded {len(ips)} IPs from subnet {subnet}")
            except ValueError as e:
                print(f"Error parsing subnet {subnet}: {e}")

        return all_ips

    def scan_subnets(self, subnets: List[str]) -> List[Dict]:
        """Scan multiple subnets concurrently"""
        print(f"\n{'='*60}")
        print(f"Cloudflare Edge IP Scanner")
        print(f"{'='*60}")
        print(f"Test Domain: {self.test_domain}")
        print(f"Timeout: {self.timeout}s")
        print(f"Max Workers: {self.max_workers}")
        print(f"Port: {self.port}")
        print(f"Download Test: {self.test_download}")
        print(f"{'='*60}\n")

        # Generate all IPs
        print("Generating IP list from subnets...")
        ip_list = self.generate_ips_from_subnets(subnets)
        self.total_ips = len(ip_list)

        if self.total_ips == 0:
            print("No IPs to scan!")
            return []

        print(f"Total IPs to scan: {self.total_ips}\n")

        # Start scanning
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_ip, ip): ip for ip in ip_list}

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    pass

        end_time = time.time()
        elapsed = end_time - start_time

        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"{'='*60}")
        print(f"Total IPs scanned: {self.tested_count}")
        print(f"Working IPs found: {len(self.results)}")
        print(f"Time elapsed: {elapsed:.2f}s")
        print(f"Scan rate: {self.tested_count/elapsed:.2f} IPs/s")
        print(f"{'='*60}\n")

        # Sort results by latency
        self.results.sort(key=lambda x: x.get('latency_ms', float('inf')))

        return self.results

    def save_results(self, filename: str = "working_ips.json"):
        """Save results to JSON file"""
        output = {
            'scan_date': datetime.now().isoformat(),
            'test_domain': self.test_domain,
            'total_scanned': self.tested_count,
            'working_ips_count': len(self.results),
            'working_ips': self.results
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"Results saved to {filename}")

        # Also save simple IP list
        txt_filename = filename.replace('.json', '.txt')
        with open(txt_filename, 'w', encoding='utf-8') as f:
            for result in self.results:
                f.write(f"{result['ip']}\n")

        print(f"IP list saved to {txt_filename}")

    def print_top_ips(self, count: int = 10):
        """Print top working IPs"""
        if not self.results:
            print("No working IPs found!")
            return

        print(f"\nTop {min(count, len(self.results))} Working IPs:")
        print(f"{'='*80}")
        print(f"{'IP Address':<18} {'Latency':<12} {'Speed':<15} {'Status'}")
        print(f"{'-'*80}")

        for i, result in enumerate(self.results[:count]):
            ip = result['ip']
            latency = f"{result['latency_ms']}ms"
            speed = f"{result.get('speed_kbps', 0):.2f} KB/s" if 'speed_kbps' in result else "N/A"
            status = result['status']

            print(f"{ip:<18} {latency:<12} {speed:<15} {status}")

        print(f"{'='*80}\n")


def load_subnets_from_file(filename: str = 'subnets.txt') -> List[str]:
    """Load subnets from a text file (one subnet per line)"""
    subnets = []

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    subnets.append(line)

        print(f"Loaded {len(subnets)} subnets from {filename}")
        return subnets
    except FileNotFoundError:
        return []


def main():
    # Load configuration
    try:
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
    except FileNotFoundError:
        print("config.json not found! Creating default configuration...")
        config = {
            'test_domain': 'chatgpt.com',
            'test_path': '/',
            'timeout': 3,
            'max_workers': 100,
            'test_download': True,
            'download_size': 102400,
            'port': 443,
            'subnets': [
                '104.18.0.0/20',
                '172.64.0.0/20'
            ]
        }

        with open('config.json', 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        print("Default config.json created. Please edit and run again.")
        return

    # Get subnets - prioritize subnets.txt file if it exists
    subnets = load_subnets_from_file('subnets.txt')

    # If no subnets.txt, fall back to config.json
    if not subnets:
        subnets = config.get('subnets', [])

    if not subnets:
        print("No subnets found!")
        print("Please either:")
        print("  1. Create subnets.txt with one subnet per line, OR")
        print("  2. Add subnets to config.json")
        return

    # Create scanner
    scanner = CloudflareScanner(config)

    # Run scan
    results = scanner.scan_subnets(subnets)

    # Print top IPs
    scanner.print_top_ips(20)

    # Save results
    scanner.save_results()

    print("\nScan completed successfully!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user!")
        sys.exit(0)
