import psutil
import time
import subprocess
import re
import socket
import speedtest
import threading
import asyncio
import aiohttp
from flask import Flask, render_template, jsonify
import ipaddress
from scapy.all import ARP, Ether, srp, sniff
import requests
import platform
import ping3

app = Flask(__name__)

last_download_speed = 0
last_upload_speed = 0
last_ping = 0
last_bandwidth_sent = 0
last_bandwidth_recv = 0
last_latency = 0
last_packet_loss = 0
private_ip = None
public_ip = None
network_address = None
subnet = None
router_info = None
default_gateway = None
connected_devices = []
ipv4_routing_table = []
captured_packets = []

data_lock = threading.Lock()

ipv4_routing_table_cache = None
last_route_fetch_time = 0
CACHE_LIFETIME = 600

def get_ipv4_routes():
    global ipv4_routing_table_cache, last_route_fetch_time
    if time.time() - last_route_fetch_time < CACHE_LIFETIME:
        return ipv4_routing_table_cache

    result = subprocess.run("route print", capture_output=True, text=True, shell=True)
    routes = []
    lines = result.stdout.splitlines()
    start_line = None
    for i, line in enumerate(lines):
        if "Network Destination" in line:
            start_line = i + 1
            break
    if start_line:
        for line in lines[start_line:]:
            parts = line.split()
            if len(parts) == 5:
                route = {
                    'destination': parts[0],
                    'netmask': parts[1],
                    'gateway': parts[2] if parts[2] != "On-link" else "On-link",
                    'interface': parts[3],
                    'metric': parts[4]
                }
                routes.append(route)
    ipv4_routing_table_cache = routes
    last_route_fetch_time = time.time()
    return routes


def get_connected_devices_scapy():
    try:
        devices = []
        ip_range = socket.gethostbyname(socket.gethostname())[:-1] + '0/24'
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        request_packet = broadcast/arp_request
        result = srp(request_packet, timeout=1, verbose=False)[0]
        for sent, received in result:
            try:
                device_name = socket.gethostbyaddr(received.psrc)[0]
            except socket.herror:
                device_name = received.psrc
            devices.append({
                "name": device_name,
                "ip": received.psrc,
                "mac": received.hwsrc,
                "status": "متصل"
            })
        return devices
    except Exception as e:
        print(f"Error getting connected devices: {e}")
        return []

async def get_public_ip_async():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ipify.org') as response:
                public_ip = await response.text()
        return public_ip
    except Exception as e:
        print(f"Error retrieving public IP: {e}")
        return "N/A"

def list_interfaces():
    interfaces = psutil.net_io_counters(pernic=True).keys()
    return list(interfaces)

def calculate_bandwidth(bytes_sent, bytes_recv, interval):
    bandwidth_sent = round((bytes_sent * 8 / interval) / (10**6), 2) 
    bandwidth_recv = round((bytes_recv * 8 / interval) / (10**6), 2) 
    return bandwidth_sent, bandwidth_recv


def get_packet_loss():
    try:
        packet_loss = subprocess.check_output("ping -n 4 1.1.1.1", shell=True)
        packet_loss = re.search(r"Lost = (\d+)", packet_loss.decode())
        return int(packet_loss.group(1))
    except Exception as e:
        print(f"Error getting packet loss: {e}")


def speed_test():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download() // 1_000_000
        upload_speed = st.upload() // 1_000_000
        
        ping = ping3.ping('1.1.1.1', unit='ms')
        packet_loss = get_packet_loss()
        latency = round(requests.get('https://one.one.one.one').elapsed.total_seconds() * 1000, 2)
        
        global last_download_speed, last_upload_speed, last_ping, last_packet_loss, last_latency
        with data_lock:
            last_download_speed = download_speed
            last_upload_speed = upload_speed
            last_ping = int(ping)
            last_packet_loss = packet_loss
            last_latency = latency 
    except speedtest.SpeedtestCLIError as e:
        print(f"Error performing speed test: {e}")
        with data_lock:
            last_download_speed = 0
            last_upload_speed = 0
            last_ping = 0
            last_packet_loss = 0
            last_latency = 0
    except Exception as e:
        print(f"Unexpected error performing speed test: {e}")
        with data_lock:
            last_download_speed = 0
            last_upload_speed = 0
            last_ping = 0
            last_packet_loss = 0
            last_latency = 0



def periodic_speed_test(interval=3):
    while True:
        speed_test()
        time.sleep(interval)

def get_interface_usage(interface, interval):
    try:
        net_io = psutil.net_io_counters(pernic=True)[interface]
        if net_io:
            bandwidth_sent, bandwidth_recv = calculate_bandwidth(net_io.bytes_sent, net_io.bytes_recv, interval)
            with data_lock:
                global last_bandwidth_sent, last_bandwidth_recv
                last_bandwidth_sent = bandwidth_sent
                last_bandwidth_recv = bandwidth_recv
    except KeyError:
        print(f"Error: Interface {interface} not found.")
    except Exception as e:
        print(f"Error getting interface usage: {e}")

def periodic_lbw_test(interval=3):
    while True:
        get_interface_usage("Wi-Fi", interval)
        time.sleep(interval)

def get_private_public_ip_address():
    try:
        interfaces = psutil.net_if_addrs()
        for interface_name, interface_info in interfaces.items():
            for addr in interface_info:
                if addr.family == socket.AF_INET:
                    private_ip = addr.address
                    netmask = addr.netmask
                    if private_ip and netmask:
                        if not private_ip.startswith('169.254'):
                            return private_ip, netmask
        return None, None
    except Exception as e:
        print(f"Error getting IP address: {e}")
        return None, None

def get_network_info(ip, netmask):
    try:
        ip_obj = ipaddress.ip_interface(f"{ip}/{netmask}")
        network = ip_obj.network
        network_address = network.network_address
        subnet = network.prefixlen
        return str(network_address), subnet
    except ValueError:
        return "N/A", "N/A"

def get_router_info():
    try:
        result = subprocess.check_output('netstat -rn', shell=True, text=True)
        for line in result.splitlines():
            if "0.0.0.0" in line:
                parts = line.split()
                default_gateway = parts[2]
                break
        try:
            router_info = socket.gethostbyaddr(default_gateway)[0]
        except socket.herror:
            router_info = default_gateway
        return router_info, default_gateway
    except Exception as e:
        print(f"Error retrieving router information: {e}")
        return None, None

def packet_callback(packet):
    """Callback function to process captured packets."""
    try:
        packet_data = {
            "source_ip": packet[0][1].src if packet.haslayer("IP") else "N/A",
            "destination_ip": packet[0][1].dst if packet.haslayer("IP") else "N/A",
            "protocol": packet[0].summary().split()[0],
            "size": len(packet),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }
        with data_lock:
            if len(captured_packets) >= 100:  #100 packets
                captured_packets.pop(0)
            captured_packets.append(packet_data)
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_packet_capture():
    sniff(prn=packet_callback, store=False)

@app.route('/', methods=['GET'])
def index():
    with data_lock:
        global private_ip, netmask, network_address, subnet, router_info, default_gateway, public_ip, connected_devices, ipv4_routing_table, captured_packets

        private_ip, netmask = get_private_public_ip_address()
        if private_ip and netmask:
            network_address, subnet = get_network_info(private_ip, netmask)
        else:
            network_address, subnet = "N/A", "N/A"

        router_info, default_gateway = get_router_info()
        public_ip = public_ip or asyncio.run(get_public_ip_async())
        ipv4_routing_table = get_ipv4_routes()[:-1]
        connected_devices = get_connected_devices_scapy()

    return render_template(
        'index.html',
        connected_devices=connected_devices,
        ipv4_routing_table=ipv4_routing_table,
        captured_packets=captured_packets
    )

@app.route('/speed_data', methods=['GET'])
def speed_data():
    connected_devices = len(get_connected_devices_scapy())
    with data_lock:
        return jsonify({
            "download_speed": last_download_speed,
            "upload_speed": last_upload_speed,
            "ping": last_ping,
            "bandwidth_sent": last_bandwidth_sent,
            "bandwidth_recv": last_bandwidth_recv,
            "latency": last_latency,
            "packet_loss": last_packet_loss,
            "router_info": router_info,
            "default_gateway": default_gateway,
            "private_ip": private_ip,
            "public_ip": public_ip,
            "network_address": network_address,
            "connected_devices": connected_devices,
            "ipv4_routing_table": len(ipv4_routing_table)
        })

if __name__ == "__main__":
    speed_test_thread = threading.Thread(target=periodic_speed_test, args=(3,))
    speed_test_thread.daemon = True
    speed_test_thread.start()

    lbw_test_thread = threading.Thread(target=periodic_lbw_test, args=(3,))
    lbw_test_thread.daemon = True
    lbw_test_thread.start()

    packet_capture_thread = threading.Thread(target=start_packet_capture)
    packet_capture_thread.daemon = True
    packet_capture_thread.start()

    app.run(host='0.0.0.0', port=5500, threaded=True)
