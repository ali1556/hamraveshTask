import re
import sys
import time 
import gzip
import argparse
import json

#parsers
parser = argparse.ArgumentParser()
parser.add_argument('file', help='Path to the access log file (.log or .gz)')
parser.add_argument('--top', type=int, default=10)
parser.add_argument('--start', help='format: "01/Jun/2026:00:00:00"')
parser.add_argument('--end', help='format: "01/Jun/2026:00:00:00"')
parser.add_argument('--json', action='store_true')
args = parser.parse_args()

#vars
invalid_line_count = 0
valid_line_count = 0
total_number_of_requests = 0
unique_ip_addresses = set()
ip_traffic_counts = {}
addresses_with_most_traffic = {}
number_of_errors = 0
error_rate = 0.0
traffic_per_hour = {}
log_size = 0
ip_total_requests = {}
ip_401_requests = {}
suspicious_ips = []

#regex
log_pattern = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Za-z]+) (?P<path>[^ ]+) HTTP/\d\.\d" (?P<status>\d{3}) (?P<bytes>\d+|-{1}) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"\r?$'
)

def is_valid_log(line):
    line = line.strip()
    if not line :
        return False, None, "Empty line"
    match = log_pattern.match(line)
    if not match:
        return False, None, "Invalid log format"
    data = match.groupdict()
    return True, data, None

def endpoint_handle(endpoint):
    if endpoint in addresses_with_most_traffic:
        addresses_with_most_traffic[endpoint] += 1
    else:
        addresses_with_most_traffic[endpoint] = 1

def top_ten_addresses(n=10):
    sorted_endpoints = sorted(addresses_with_most_traffic.items(), key=lambda x: x[1], reverse=True)
    return sorted_endpoints[:n]


def calculate_error_rate():
    if total_number_of_requests > 0:
        return (number_of_errors / total_number_of_requests) * 100
    return 0.0

def print_top_endpoints(n=10):
    print(f"Top {n} Endpoints with Most Traffic:")
    print(f"{'Rank':<6} {'Endpoint':<40} {'Requests':<10}")
    for rank, (endpoint, count) in enumerate(top_ten_addresses(n), start=1):   
        endpoint_display = endpoint[:37] + "..." if len(endpoint) > 40 else endpoint
        print(f"{rank:<6} {endpoint_display:<40} {count:<10}")    


def print_hourly_traffic(traffic_per_hour):
    max_count = max(traffic_per_hour.values())
    # scale 
    scale = 30 / max_count if max_count > 0 else 0

    for hour in sorted(traffic_per_hour.keys()):
        count = traffic_per_hour[hour]
        bar_length = int(count * scale)
        bar = '█' * bar_length
        print(f"  {hour}:00  | {bar} ({count})")
    peak = max(traffic_per_hour, key=traffic_per_hour.get)
    low = min(traffic_per_hour, key=traffic_per_hour.get)
    print(f"  Peak: {peak}:00  |  Low: {low}:00")

def detect_suspicious_ips(threshold=0.3, min_requests=10):
    suspicious = []
    for ip, total in ip_total_requests.items():
        if total >= min_requests:
            errors = ip_401_requests.get(ip, 0)
            rate = errors / total
            if rate >= threshold:
                suspicious.append((ip, total, errors, rate))
    return sorted(suspicious, key=lambda x: x[2], reverse=True)

#main process  

start_time = time.time()
file_path = sys.argv[1]

if args.file.endswith('.gz'):
    file = gzip.open(args.file, 'rt')
else:
    file = open(args.file, 'r')

for line in file:
    is_valid, data, error = is_valid_log(line)
    
    if is_valid:
        timestamp = data['timestamp']
        timestamp_no_tz = timestamp.split(' +')[0]  
        if args.start and timestamp_no_tz < args.start:
            continue
        if args.end and timestamp_no_tz > args.end:
            continue

    total_number_of_requests += 1

    if is_valid:    

        valid_line_count += 1
        #hourly traffic
        hour = timestamp.split(':')[1]
        traffic_per_hour[hour] = traffic_per_hour.get(hour, 0) + 1

        #endpoint count
        endpoint_handle(data['path'])

        #unique ips
        unique_ip_addresses.add(data['ip'])

        #error handle
        if data['status'].startswith('4') or data['status'].startswith('5'):
            number_of_errors += 1

        #sus ips
        ip = data['ip']
        ip_total_requests[ip] = ip_total_requests.get(ip, 0) + 1
        if data['status'] == '401':
            ip_401_requests[ip] = ip_401_requests.get(ip, 0) + 1

    else:
        invalid_line_count += 1

file.close()

suspicious_ips = detect_suspicious_ips()

elapsed_time = time.time() - start_time


if args.json:
    output = {
        "total_requests": total_number_of_requests,
        "valid_lines": valid_line_count,
        "invalid_lines": invalid_line_count,
        "unique_ips": len(unique_ip_addresses),
        "top_endpoints": top_ten_addresses(args.top),
        "error_rate": calculate_error_rate(),
        "hourly_traffic": traffic_per_hour,
        "suspicious_ips": suspicious_ips,
        "execution_time_seconds": elapsed_time
    }
    print(json.dumps(output, indent=2))
else:
    print(f"Total requests         : {total_number_of_requests}")
    print(f"Valid lines            : {valid_line_count}")
    print(f"Invalid lines          : {invalid_line_count}")
    print(f"Unique IP addresses    : {len(unique_ip_addresses)}")
    print_top_endpoints(args.top)
    print(f"\nError rate (4xx/5xx)   : {calculate_error_rate():.2f}%")
    print_hourly_traffic(traffic_per_hour)

    if suspicious_ips:
        print("\nSuspicious IPs:")
        print(f"{'IP Address':<20} {'Total Req':<12} {'401 Errors':<12} {'Error Rate':<10}")
        for ip, total, errors, rate in suspicious_ips[:10]:
            print(f"{ip:<20} {total:<12} {errors:<12} {rate*100:.2f}%")


    print(f"\nExecution time: {elapsed_time:.2f} seconds")