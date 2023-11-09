import re
from collections import defaultdict


def parse_log_line(log_line):
    # Assuming the log is in csv format
    # Fields: Date | Time | Action | Protocol | Src IP | Dst IP | Src Port | Dst Port | Size | TCP Flags | Info
    fields = log_line.strip().split(' ')

    # Ensuring that each line has the expected number of fields
    if len(fields) < 11:
        print(f"Ignoring malformed log entry: {log_line}")
        return None

    return {
        'date': fields[0],
        'time': fields[1],
        'action': fields[2],
        'protocol': fields[3],
        'src_ip': fields[4],
        'dst_ip': fields[5],
        'src_port': fields[6],
        'dst_port': fields[7],
        'size': fields[8],
        'tcp_flags': fields[9],
        'info': ' '.join(fields[10:])  # Join the rest as Info
    }


def detect_threats(log_data):
    if log_data['action'] == 'BLOCK':
        print(f"Potential threat detected: {log_data}")


def analyze_logs(log_file_path):
    total_logs = 0
    block_count = 0
    allow_count = 0

    src_ip_count = defaultdict(int)
    dst_ip_count = defaultdict(int)
    src_ip_block = []

    with open(log_file_path, 'r') as log_file:
        next(log_file) #skip the first line
        for line in log_file:
            log_data = parse_log_line(line)
            if log_data is not None:
                detect_threats(log_data)
                total_logs += 1
                if log_data['action'] == 'BLOCK':
                    block_count += 1
                    if log_data['src_ip'] not in src_ip_block:
                        src_ip_block.append(log_data['src_ip'])
                elif log_data['action'] == 'ALLOW':
                    allow_count += 1

                src_ip_count[log_data['src_ip']] += 1
                dst_ip_count[log_data['dst_ip']] += 1

    print()
    print(f"Total logs: {total_logs}")
    print(f"BLOCK actions: {block_count}")
    print(f"ALLOW actions: {allow_count}")

    print("\nTop Source IPs:")
    for src_ip, count in sorted(src_ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{src_ip}: {count} times")

    print("\nTop Destination IPs:")
    for dst_ip, count in sorted(dst_ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{dst_ip}: {count} times")

    print("\nRequest action='BLOCK' IPs:")
    for ip in src_ip_block:
        print(f"{ip}")


if __name__ == "__main__":
    log_file_path = "sample_log.csv"
    analyze_logs(log_file_path)