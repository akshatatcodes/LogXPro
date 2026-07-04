"""
ingestion/file_parser.py
------------------------
Parses forensic artifacts (PCAP, Zeek, JSON, CSV, Syslog) and normalizes them to ECS.
"""
import os
import re
import csv
import json
import subprocess
import shutil
from datetime import datetime, timezone
from typing import List, Dict, Any


def get_any_key(d: dict, keys: list) -> Any:
    for k in keys:
        if k in d:
            return d[k]
    return None


def parse_timestamp(val: Any) -> str:
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(float(val), tz=timezone.utc).isoformat()
        except Exception:
            pass
    if isinstance(val, str):
        val_clean = val.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(val_clean).isoformat()
        except Exception:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y/%m/%d %H:%M:%S", "%b %d %H:%M:%S"):
            try:
                dt = datetime.strptime(val, fmt)
                if fmt == "%b %d %H:%M:%S":
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                return dt.replace(tzinfo=timezone.utc).isoformat()
            except Exception:
                pass
    return datetime.now(timezone.utc).isoformat()


def map_json_to_ecs(item: dict) -> dict:
    ecs = {}
    
    source_ip = get_any_key(item, ['src_ip', 'source_ip', 'src', 'source_address', 'SrcIP', 'IpAddress', 'ip_address'])
    dest_ip = get_any_key(item, ['dest_ip', 'destination_ip', 'dst', 'destination_address', 'DstIP'])
    source_port = get_any_key(item, ['src_port', 'source_port', 'SrcPort', 'sport'])
    dest_port = get_any_key(item, ['dest_port', 'destination_port', 'DstPort', 'dport'])
    
    host_name = get_any_key(item, ['host_name', 'computer_name', 'computer', 'hostname', 'ComputerName', 'Computer'])
    user_name = get_any_key(item, ['username', 'user_name', 'user', 'UserName', 'TargetUserName'])
    
    proc_exec = get_any_key(item, ['process_name', 'image', 'proc_name', 'Image', 'executable'])
    proc_cmd = get_any_key(item, ['command_line', 'cmdline', 'CommandLine', 'arguments'])
    proc_pid = get_any_key(item, ['process_id', 'pid', 'ProcessId', 'PID'])
    
    parent_exec = get_any_key(item, ['parent_image', 'ParentImage', 'parent_process_name'])
    parent_cmd = get_any_key(item, ['parent_command_line', 'ParentCommandLine'])
    
    evt_code = get_any_key(item, ['event_id', 'event_code', 'EventID', 'EventCode'])
    ts = get_any_key(item, ['timestamp', 'time', 'ts', '@timestamp', 'date', 'event_time', 'EventTime', 'system_time'])
    
    ecs['@timestamp'] = parse_timestamp(ts) if ts else datetime.now(timezone.utc).isoformat()
    
    if source_ip or source_port:
        ecs['source'] = {}
        if source_ip: ecs['source']['ip'] = str(source_ip)
        if source_port:
            try: ecs['source']['port'] = int(source_port)
            except Exception: pass
            
    if dest_ip or dest_port:
        ecs['destination'] = {}
        if dest_ip: ecs['destination']['ip'] = str(dest_ip)
        if dest_port:
            try: ecs['destination']['port'] = int(dest_port)
            except Exception: pass
            
    if host_name:
        ecs['host'] = {'name': str(host_name)}
    elif 'host' in item and isinstance(item['host'], dict) and 'name' in item['host']:
        ecs['host'] = {'name': item['host']['name']}
        
    if user_name:
        ecs['user'] = {'name': str(user_name)}
    elif 'user' in item and isinstance(item['user'], dict) and 'name' in item['user']:
        ecs['user'] = {'name': item['user']['name']}
        
    if proc_exec or proc_cmd or proc_pid:
        ecs['process'] = {}
        if proc_exec: ecs['process']['executable'] = str(proc_exec)
        if proc_cmd: ecs['process']['command_line'] = str(proc_cmd)
        if proc_pid:
            try: ecs['process']['pid'] = int(proc_pid)
            except Exception: pass
            
        if parent_exec or parent_cmd:
            ecs['process']['parent'] = {}
            if parent_exec: ecs['process']['parent']['executable'] = str(parent_exec)
            if parent_cmd: ecs['process']['parent']['command_line'] = str(parent_cmd)
            
    if evt_code:
        ecs['event'] = {'code': int(evt_code) if str(evt_code).isdigit() else str(evt_code)}
    elif 'event' in item and isinstance(item['event'], dict):
        ecs['event'] = item['event']
        
    for k, v in item.items():
        if k not in ecs and k not in ['src_ip', 'source_ip', 'src', 'source_address', 'SrcIP', 'IpAddress', 'ip_address',
                                      'dest_ip', 'destination_ip', 'dst', 'destination_address', 'DstIP',
                                      'src_port', 'source_port', 'SrcPort', 'sport',
                                      'dest_port', 'destination_port', 'DstPort', 'dport',
                                      'host_name', 'computer_name', 'computer', 'hostname', 'ComputerName', 'Computer',
                                      'username', 'user_name', 'user', 'UserName', 'TargetUserName',
                                      'process_name', 'image', 'proc_name', 'Image', 'executable',
                                      'command_line', 'cmdline', 'CommandLine', 'arguments',
                                      'process_id', 'pid', 'ProcessId', 'PID',
                                      'parent_image', 'ParentImage', 'parent_process_name',
                                      'parent_command_line', 'ParentCommandLine',
                                      'event_id', 'event_code', 'EventID', 'EventCode',
                                      'timestamp', 'time', 'ts', '@timestamp', 'date', 'event_time', 'EventTime', 'system_time']:
            ecs[k] = v
            
    if 'event' not in ecs:
        ecs['event'] = {}
    if 'kind' not in ecs['event']:
        ecs['event']['kind'] = 'event'
    if 'category' not in ecs['event']:
        ecs['event']['category'] = ['host'] if 'process' in ecs or 'user' in ecs else ['network'] if 'source' in ecs or 'destination' in ecs else ['generic']
        
    return ecs


def map_zeek_to_ecs(item: dict) -> dict:
    ecs = {}
    ts = item.get('ts')
    if ts:
        try:
            ecs['@timestamp'] = datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except Exception:
            ecs['@timestamp'] = parse_timestamp(ts)
    else:
        ecs['@timestamp'] = datetime.now(timezone.utc).isoformat()
        
    src_ip = item.get('id.orig_h')
    dest_ip = item.get('id.resp_h')
    src_port = item.get('id.orig_p')
    dest_port = item.get('id.resp_p')
    
    if src_ip or src_port:
        ecs['source'] = {}
        if src_ip: ecs['source']['ip'] = str(src_ip)
        if src_port:
            try: ecs['source']['port'] = int(src_port)
            except Exception: pass
            
    if dest_ip or dest_port:
        ecs['destination'] = {}
        if dest_ip: ecs['destination']['ip'] = str(dest_ip)
        if dest_port:
            try: ecs['destination']['port'] = int(dest_port)
            except Exception: pass
            
    proto = item.get('proto')
    if proto:
        ecs['network'] = {'transport': str(proto).lower()}
        
    service = item.get('service')
    if service:
        if 'network' not in ecs:
            ecs['network'] = {}
        ecs['network']['protocol'] = str(service).lower()
        
    ecs['event'] = {
        'kind': 'event',
        'category': ['network'],
        'type': 'connection'
    }
    
    query = item.get('query')
    if query:
        ecs['dns'] = {'question': {'name': str(query)}}
        
    method = item.get('method')
    uri = item.get('uri')
    if method or uri:
        ecs['http'] = {}
        if method: ecs['http']['request'] = {'method': str(method).upper()}
        if uri:
            ecs['http']['request'] = ecs['http'].get('request', {})
            ecs['http']['request']['uri'] = str(uri)
            
    for k, v in item.items():
        if k not in ['id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p', 'ts', 'proto', 'service']:
            clean_k = k.replace('.', '_')
            ecs[clean_k] = v
            
    return ecs


def parse_pcap(file_path: str) -> List[dict]:
    # Try tshark first
    if shutil.which("tshark"):
        try:
            cmd = ["tshark", "-r", file_path, "-T", "json"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            packets = json.loads(res.stdout)
            events = []
            for packet in packets:
                layers = packet.get("_source", {}).get("layers", {})
                if not layers:
                    continue
                    
                frame_time = layers.get("frame", {}).get("frame.time_epoch")
                if not frame_time:
                    continue
                    
                try:
                    dt = datetime.fromtimestamp(float(frame_time), tz=timezone.utc)
                    timestamp = dt.isoformat()
                except Exception:
                    timestamp = datetime.now(timezone.utc).isoformat()
                    
                ip_src = layers.get("ip", {}).get("ip.src") or layers.get("ipv6", {}).get("ipv6.src")
                ip_dst = layers.get("ip", {}).get("ip.dst") or layers.get("ipv6", {}).get("ipv6.dst")
                
                tcp_layer = layers.get("tcp", {})
                udp_layer = layers.get("udp", {})
                
                src_port = tcp_layer.get("tcp.srcport") or udp_layer.get("udp.srcport")
                dst_port = tcp_layer.get("tcp.dstport") or udp_layer.get("udp.dstport")
                
                proto = None
                if tcp_layer:
                    proto = "tcp"
                elif udp_layer:
                    proto = "udp"
                    
                event_dict = {
                    "@timestamp": timestamp,
                    "event": {
                        "kind": "event",
                        "category": ["network"],
                        "type": "connection",
                        "code": 3
                    }
                }
                
                if ip_src or src_port:
                    event_dict["source"] = {}
                    if ip_src: event_dict["source"]["ip"] = str(ip_src)
                    if src_port:
                        try: event_dict["source"]["port"] = int(src_port)
                        except Exception: pass
                        
                if ip_dst or dst_port:
                    event_dict["destination"] = {}
                    if ip_dst: event_dict["destination"]["ip"] = str(ip_dst)
                    if dst_port:
                        try: event_dict["destination"]["port"] = int(dst_port)
                        except Exception: pass
                        
                if proto:
                    event_dict["network"] = {"transport": proto}
                    
                tls_layer = layers.get("tls", {})
                if tls_layer:
                    tls_data = {}
                    sni = tls_layer.get("tls.handshake.extensions_server_name")
                    if sni:
                        tls_data["server"] = {"name": str(sni)}
                    version = tls_layer.get("tls.handshake.version")
                    if version:
                        tls_data["version"] = str(version)
                    if tls_data:
                        event_dict["tls"] = tls_data
                        
                events.append(event_dict)
            return events
        except Exception as e:
            print(f"[!] tshark execution failed, falling back to scapy: {e}")

    # Fallback to Scapy
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP
    except ImportError:
        raise RuntimeError("Neither tshark is installed nor scapy package is available to parse PCAP files.")

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        raise RuntimeError(f"Scapy failed to read PCAP: {e}")

    events = []
    for pkt in packets:
        try:
            timestamp = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()
        except Exception:
            timestamp = datetime.now(timezone.utc).isoformat()

        ip_src = None
        ip_dst = None
        src_port = None
        dst_port = None
        proto = None

        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            ip_src = pkt[IPv6].src
            ip_dst = pkt[IPv6].dst

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "tcp"
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "udp"

        if not ip_src and not ip_dst:
            continue

        event_dict = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["network"],
                "type": "connection",
                "code": 3
            }
        }
        if ip_src or src_port:
            event_dict["source"] = {}
            if ip_src: event_dict["source"]["ip"] = str(ip_src)
            if src_port: event_dict["source"]["port"] = int(src_port)
        if ip_dst or dst_port:
            event_dict["destination"] = {}
            if ip_dst: event_dict["destination"]["ip"] = str(ip_dst)
            if dst_port: event_dict["destination"]["port"] = int(dst_port)
        if proto:
            event_dict["network"] = {"transport": proto}

        # Try extract server name if it's ClientHello (very lightweight/simple check to avoid importing heavy TLS headers)
        if proto == "tcp" and dst_port == 443 and pkt.haslayer(TCP) and pkt[TCP].payload:
            payload = bytes(pkt[TCP].payload)
            if len(payload) > 5 and payload[0] == 0x16:  # Handshake
                try:
                    # Look for server name string in the payload
                    # Very simple heuristic: search for common hostnames or indicators
                    # Normally we'd parse TLS client hello, but we can do simple detection or rely on basic network flow.
                    pass
                except Exception:
                    pass

        events.append(event_dict)

    return events


def parse_zeek(file_path: str) -> List[dict]:
    events = []
    # Try Zeek JSON first
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        events.append(map_zeek_to_ecs(item))
                except json.JSONDecodeError:
                    break
            if events:
                return events
    except Exception:
        pass

    # Try Zeek TSV log parsing
    events = []
    fields = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip('\n')
            if not line:
                continue
            if line.startswith('#fields'):
                fields = line.split('\t')[1:]
                continue
            if line.startswith('#'):
                continue
            if not fields:
                continue
            
            parts = line.split('\t')
            if len(parts) != len(fields):
                continue
            
            row = dict(zip(fields, parts))
            for k, v in row.items():
                if v == '-' or v == '(empty)':
                    row[k] = None
                    
            events.append(map_zeek_to_ecs(row))
    return events


def parse_json(file_path: str) -> List[dict]:
    events = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        events.append(map_json_to_ecs(item))
                return events
            elif isinstance(data, dict):
                return [map_json_to_ecs(data)]
    except json.JSONDecodeError:
        pass
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    events.append(map_json_to_ecs(item))
            except json.JSONDecodeError:
                pass
    return events


def parse_csv(file_path: str) -> List[dict]:
    events = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(map_json_to_ecs(row))
    return events


def parse_syslog(file_path: str) -> List[dict]:
    events = []
    bsd_pattern = re.compile(
        r'^(?:<(?P<pri>\d+)>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[^\s]+)\s+(?P<process>[a-zA-Z0-9_\-\./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
    )
    rfc5424_pattern = re.compile(
        r'^(?:<(?P<pri>\d+)>)?\d+\s+(?P<timestamp>[^\s]+)\s+(?P<host>[^\s]+)\s+(?P<process>[^\s]+)\s+(?P<pid>[^\s]+)\s+(?P<msgid>[^\s]+)\s+(?:(?P<sdata>\[[^\]]+\])|-)\s+(?P<message>.*)$'
    )
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            m = rfc5424_pattern.match(line)
            if m:
                gd = m.groupdict()
                timestamp = parse_timestamp(gd.get('timestamp'))
                host = gd.get('host')
                process = gd.get('process')
                pid = gd.get('pid')
                message = gd.get('message')
                
                evt = {
                    "@timestamp": timestamp,
                    "event": {
                        "kind": "event",
                        "category": ["syslog"],
                        "type": "info"
                    },
                    "message": message
                }
                if host and host != '-':
                    evt["host"] = {"name": host}
                if process and process != '-':
                    evt["process"] = {"name": process}
                if pid and pid != '-':
                    try:
                        evt["process"] = evt.get("process", {})
                        evt["process"]["pid"] = int(pid)
                    except Exception:
                        pass
                events.append(evt)
                continue
                
            m = bsd_pattern.match(line)
            if m:
                gd = m.groupdict()
                ts_str = gd.get('timestamp')
                try:
                    dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                    timestamp = dt.replace(tzinfo=timezone.utc).isoformat()
                except Exception:
                    timestamp = datetime.now(timezone.utc).isoformat()
                    
                host = gd.get('host')
                process = gd.get('process')
                pid = gd.get('pid')
                message = gd.get('message')
                
                evt = {
                    "@timestamp": timestamp,
                    "event": {
                        "kind": "event",
                        "category": ["syslog"],
                        "type": "info"
                    },
                    "message": message
                }
                if host:
                    evt["host"] = {"name": host}
                if process:
                    evt["process"] = {"name": process}
                if pid:
                    try:
                        evt["process"] = evt.get("process", {})
                        evt["process"]["pid"] = int(pid)
                    except Exception:
                        pass
                events.append(evt)
                continue
                
            events.append({
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "event": {
                    "kind": "event",
                    "category": ["syslog"],
                    "type": "info"
                },
                "message": line
            })
            
    return events


def detect_file_type(filename: str, temp_path: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    if ext in ['.pcap', '.pcapng']:
        return 'pcap'
    if ext == '.csv':
        return 'csv'
        
    try:
        with open(temp_path, 'rb') as f:
            magic = f.read(4)
            if magic in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x0a\x0d\x0d\x0a']:
                return 'pcap'
    except Exception:
        pass

    try:
        with open(temp_path, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline()
            if first_line.startswith('#separator') or first_line.startswith('#fields') or first_line.startswith('#types'):
                return 'zeek'
            
            try:
                json.loads(first_line)
                return 'json'
            except json.JSONDecodeError:
                pass
            
            bsd_syslog_re = r'^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            rfc5424_syslog_re = r'^(?:<\d+>)?\d+\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
            if re.match(bsd_syslog_re, first_line) or re.match(rfc5424_syslog_re, first_line):
                return 'syslog'

            if ext in ['.json', '.jsonl']:
                return 'json'
            if ext in ['.log', '.txt']:
                f.seek(0)
                lines = [f.readline() for _ in range(5)]
                for line in lines:
                    if line.startswith('#fields'):
                        return 'zeek'
                    if re.match(bsd_syslog_re, line) or re.match(rfc5424_syslog_re, line):
                        return 'syslog'
    except Exception:
        pass
    
    return 'unknown'


def parse_file(file_path: str, file_type: str, original_filename: str) -> List[dict]:
    parsers = {
        'pcap': parse_pcap,
        'zeek': parse_zeek,
        'json': parse_json,
        'csv': parse_csv,
        'syslog': parse_syslog,
    }
    
    parser_fn = parsers.get(file_type)
    if not parser_fn:
        raise ValueError(f"Unsupported file type: {file_type}")
        
    return parser_fn(file_path)
