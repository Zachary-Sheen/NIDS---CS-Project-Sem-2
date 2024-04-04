import sys
from scapy.all import *
import tkinter as tk
import re
# from PyQt5.QtWidgets import *
# from PyQt5 import QtCore, QtGui, QtWidgets
import threading
from PySide6 import QtCore, QtWidgets, QtGui
import requests


# cd Desktop/NIDS 
# python3 main.py


       

#region Regex Threats
threat_signatures = {
    "sql_injection": re.compile(r'.*SELECT.*FROM.*'),
    "xss_attack": re.compile(r'<script>.*</script>'),
    "command_injection": re.compile(r'.*\b(?:rm|del|exec|system)\b.*'),
    "directory_traversal": re.compile(r'\.\./'),
    "rce_attack": re.compile(r'\b(?:eval|exec|system)\b'),
    "file_inclusion": re.compile(r'\b(?:include|require|require_once|include_once)\b'),
    "csrf_attack": re.compile(r'\<form.*\saction=\"(?!your-site.com)'),
    "credential_harvesting": re.compile(r'password|pwd|pass|login|username'),
    "brute_force_attack": re.compile(r'Login failed for user'),
    "malware_download": re.compile(r'\.exe|\.dll|\.bat|\.zip'),
    "data_exfiltration": re.compile(r'POST\s(?!your-site.com)'),
    "phishing_attempt": re.compile(r'Your\saccount\shas\sexpired'),
    "dns_tunneling": re.compile(r'([A-Za-z0-9+-]+\.)+[A-Za-z]{2,6}'),
    "malicious_redirect": re.compile(r'Location:\shttp://malicious-site.com'),
    "shell_upload": re.compile(r'multipart/form-data;.*filename=\".*\.(php|asp|aspx|jsp)\"'),
    "xds_attack": re.compile(r'<iframe\s.*src=\"(?!your-site.com)'),
    "blind_sql_injection": re.compile(r'Sleep\(.*\)|BENCHMARK\(.*\)'),
    "buffer_overflow": re.compile(r'(?:overflow|stack smashing detected)'),
    "malicious_file_upload": re.compile(r'multipart/form-data;.*filename=\".*\.(exe|dll|py|sh|cmd)\"'),
    "mitm_attack": re.compile(r'sslstrip|sslsniff|mitmproxy'),
    "network_reconnaissance": re.compile(r'nmap|ping|traceroute'),
    "ssh_bruteforce": re.compile(r'Failed password for .* from <IP> port \d+'),
    "ftp_bruteforce": re.compile(r'530 Login incorrect'),
    "smtp_bruteforce": re.compile(r'535 5.7.8 Authentication credentials'),
    "http_response_splitting": re.compile(r'Content-Length:\s0'),
    "exploit_kit_activity": re.compile(r'\.php\?action='),
    "zero_day_exploit_attempt": re.compile(r'0day|CVE-\d+-\d+'),
    "ddos_attack": re.compile(r'SYN flood|UDP flood|ICMP flood'),
    "dos_attack": re.compile(r'denied.*due to rate control'),
    "malicious_javascript": re.compile(r'eval\(.*\)|document\.write\(.*\)|\.src\s*=\s*\"(?!your-site.com)'),
    "drive_by_download": re.compile(r'Content-Disposition: attachment'),
    "file_deletion_attempt": re.compile(r'unlink\(.*\)|remove\(.*\)|delete\(.*\)|rmdir\(.*\)|destroy\(.*\)|shell_exec\(.*\)|exec\(.*\)|system\(.*\)|passthru\(.*\)|proc_open\(.*\)|popen\(.*\)|chown\(.*\)|chmod\(.*\)|truncate\(.*\)|touch\(.*\)|fput\(.*\)|fwrite\(.*\)|fwrite\(.*\)|fputs\(.*\)|rename\(.*\)|fopen\(.*\)|copy\(.*\)|unlink\(.*\)|curl_\w+\(.*\)|file_get_contents\(.*\)|fread\(.*\)|readfile\(.*\)|fsockopen\(.*\)|pcre\s*\(\s*["\']\s*[A-Z0-9!@#$%^&*()]+\s*["\']\s*\)|preg_match\(.*\)|preg_replace\(.*\)|preg_split\(.*\)|preg_grep\(.*\)|preg_filter\(.*\)|mysql_query\(.*\)|mysql_fetch_assoc\(.*\)|mysql_fetch_array\(.*\)|mysql_fetch_row\(.*\)|mysql_fetch_object\(.*\)|mysql_num_rows\(.*\)|mysql_insert_id\(.*\)|mysql_error\(.*\)|mysqli_query\(.*\)|mysqli_fetch_assoc\(.*\)|mysqli_fetch_array\(.*\)|mysqli_fetch_row\(.*\)|mysqli_fetch_object\(.*\)|mysqli_num_rows\(.*\)|mysqli_insert_id\(.*\)|mysqli_error\(.*\)|shell\(\s*["\']\s*[A-Z0-9!@#$%^&*()]+\s*["\']\s*\)'),
    "arp_spoofing": re.compile(r'ARP reply .* is-at .*'),
    "sql_dump_attempt": re.compile(r'\b(?:sql_dump|backup)\b'),
    "malicious_office_doc": re.compile(r'\.(?:docm|xlsm|pptm)'),
    "dns_hijacking": re.compile(r'Hijack|DNS response modified'),
    "malvertising": re.compile(r'onclick=.*http://malicious-site.com'),
    "pharming_attack": re.compile(r'Redirecting to .*'),
    "ransomware_activity": re.compile(r'Your files have been encrypted'),
    "malicious_email_attachment": re.compile(r'Content-Disposition: attachment; filename=".*\.(exe|dll|zip|js)"'),
    "cryptojacking": re.compile(r'Coinhive|Monero'),
    "session_hijacking": re.compile(r'sessionid=.*;'),
    "malicious_registry_entry": re.compile(r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'),
    "malicious_mobile_app": re.compile(r'package:\scom\.malicious'),
    "drive_lockout_attempt": re.compile(r'\b(?:sudo rm -rf /|format C:)\b'),
    "rootkit_activity": re.compile(r'\b(?:rootkit|system trojan|kernel exploit)\b'),
    "dns_amplification": re.compile(r'dnseval'),
    "malicious_usb_device": re.compile(r'USB Device ID: .*'),
    "malicious_browser_extension": re.compile(r'chrome-extension://malicious|moz-extension://malicious'),
    "reverse_shell_attempt": re.compile(r'reverse shell|nc -e /bin/sh')
}
headers = { #API connection and json formatted response
'Key': "5702b64cdeddfd1d883861dd68b4bdc19342294d213253d1eb66946541c40abdc2b6023b5360db95",
'Accept': 'application/json'
}
#endregion Regex Threats
def packet_handler(packet):
    print(packet.summary)

def is_malicious(packet_payload, threat_signatures,sourceip):
    packet_payload_str = packet_payload.decode('utf-8')  #latin-1, utf-16, utf-32
    key = "5702b64cdeddfd1d883861dd68b4bdc19342294d213253d1eb66946541c40abdc2b6023b5360db95"  #API integration
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={sourceip}&maxAgeInDays=90'
    for signature_name, signature_regex in threat_signatures.items():
        if signature_regex.search(packet_payload_str):
            print(f"Packet is malicious. Detected signature: {signature_name}\n")
            return True
        #API code
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:  #200 means it went through
                data = response.json()
                if data['data']['abuseConfidenceScore'] >= 50:
                    print(f"The IP address {sourceip} is malicious with a confidence score of {data['data']['abuseConfidenceScore']}") #takes in the confidence score, confidence score of above 50 should be looked into
                else:
                    print(f"The IP address {sourceip} is not malicious.")
            else:
                print(f"Error: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"An error occurred: {str(e)}")
        #end API code
    
    print("Packet is not malicious.")
    return False

def parse_packet(packet):
    try:
        # Check if packet can be broken down
        if isinstance(packet, Packet):
            # Check if IP layer is in the packet
            if IP in packet:
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                protocol = packet[IP].proto
                payload_length = len(packet)
                print(f"Source IP: {source_ip}, Destination IP: {destination_ip}, Protocol: {protocol}, Payload Length: {payload_length}")


                if Raw in packet:
                    is_malicious(packet[Raw].load,threat_signatures,source_ip)
                    # print(f"Packet Payload - {packet[Raw].load}\n-------------------------------------------------------")
                
    except IndexError:
        # Doesn't stop system - just keeps going
        return None, None, None, None





def test_sql_injection_packet():
    # Craft an SQL injection packet
    sql_injection_payload = "admin' OR '1'='1';"
    sql_injection_packet = IP(dst="2.3.2.2") / TCP(dport=80) / Raw(load=f"GET /login?username={sql_injection_payload}&password=password HTTP/1.1\r\nHost: target_host\r\n\r\n")

    # Pass the packet to parse_packet for analysis
    
    parse_packet(sql_injection_packet)


def test_attack_packets():
    attack_payloads = {  #ATTACK PAYLOADS
        "SQL Injection": [
            "admin' OR '1'='1';",
            "'; DROP TABLE users; --",
            "SELECT * FROM users WHERE username='admin' AND password='password' OR '1'='1';"
        ],
        "XSS": [
            "<script>alert('XSS');</script>",
            "<img src='javascript:alert(\"XSS\")'>",
            "<svg/onload=alert('XSS')>"
        ],
        "Command Injection": [
            "; ls -la",
            "&& cat /etc/passwd",
            "| whoami"
        ]
    }

    for attack_type, payloads in attack_payloads.items():
        print(f"Testing {attack_type} packets:")
        for i, payload in enumerate(payloads, 1):
            attack_packet = IP(dst="2.3.2.2") / TCP(dport=80) / Raw(load=f"GET /login?username={payload}&password=password HTTP/1.1\r\nHost: target_host\r\n\r\n")
            print(f"-------------------------------------------------------\n\tTesting {attack_type} packet {i}:")
            parse_packet(attack_packet)
            
# test_attack_packets()

sniff(iface='eth0', prn=parse_packet, count=10) #set count to 0 to analyze indefinitely
  


  
  
  

    
    
    
    
    
  


   #Tkinter GUI Code
# window = tk.Tk()
# window.geometry("688x429")
# window.title("Network Detection Intrusion System")

# susPacks = tk.Label(window, text="Suspicious Packets", borderwidth = 2, relief = "solid",width = 60, height = 13, anchor = "n")
# susPacks.grid(row = 0, column = 0, rowspan = 3, columnspan= 5, sticky = "n")
# SPText = tk.Text(window, height = 13, width = 77,font=("MS Sans Serif", 10))
# SPText.place(relx=0, rely=0.075, anchor="nw")

# badPacks = tk.Label(window, text = " Bad Packets", borderwidth= 3, relief = "solid", width = 15, height = 4,anchor = "n")
# badPacks.grid(row = 0, column =6, sticky = "nw")
# BPText = tk.Text(window,height = 3, width = 18)
# BPText.place(relx=0.8, rely=0.05, anchor="nw")

# packs = tk.Label(window, text = "Packets", borderwidth= 3, relief = "solid", width = 15, height = 4,anchor = "n")
# packs.grid(row = 1, column =6, sticky = "nw")
# PText = tk.Text(window,height= 3, width = 18)
# PText.place(relx = 0.8, rely = 0.215, anchor = "nw")

# devide = tk.Label(window, text = " Bad Packets/Packets", borderwidth= 2, relief = "solid", width = 15, height = 4,anchor = "n")
# devide.grid(row = 2, column =6, sticky = "nw")
# DVText = tk.Text(window, height = 3, width = 18)
# DVText.place(relx = 0.8, rely = 0.38, anchor = "nw")

# allPacks = tk.Label(window, text="All Packets", borderwidth = 2, relief = "solid",width = 60, height = 13, anchor = "n")
# allPacks.grid(row = 3, column = 1, rowspan = 3, columnspan= 5, sticky = "n")
# APText = tk.Text(window, height = 13, width = 77,font=("MS Sans Serif", 10))
# APText.place(relx = 0, rely = 0.575, anchor = "nw")

# timeRun = tk.Label(window, text = "Time Running", borderwidth= 3, relief = "solid", width = 15, height = 4,anchor = "n")
# timeRun.grid(row = 3, column =6, sticky = "nw" )
# TRText = tk.Text(window, height = 3, width = 18)
# TRText.place(relx = 0.8, rely = 0.55, anchor = "nw")

# packSec = tk.Label(window, text = "Packets/sec", borderwidth= 3, relief = "solid", width = 15, height = 4,anchor = "n")
# packSec.grid(row = 4, column =6, sticky = "nw")
# PSText = tk.Text(window, height = 3, width = 18)
# PSText.place(relx = 0.8, rely = 0.72, anchor = "nw")

# packHr = tk.Label(window, text = "Packets/hr", borderwidth= 2, relief = "solid", width = 15, height = 4,anchor = "n")
# packHr.grid(row = 5, column =6, sticky = "nw")
# PHText = tk.Text(window, height = 3, width = 18)
# PHText.place(relx = 0.8, rely = 0.88, anchor = "nw")

# insert_button = tk.Button(window, text="RUN", command=runCode)
# insert_button.place(relx = 0,rely = 0, anchor = "nw")
# # insert_button.pack()

# window.mainloop()

