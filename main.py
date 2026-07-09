import re
import sys
import time 
import gzip



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


log_pattern = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^ ]+) HTTP/\d\.\d" (?P<status>\d{3}) (?P<bytes>\d+|-{1}) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"\r?$'
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

def ip_handle(ip):
    unique_ip_addresses.add(ip)

def top_ten_addresses():
    sorted_endpoints = sorted(addresses_with_most_traffic.items(), key=lambda x: x[1], reverse=True)
    return sorted_endpoints[:10]

def calculate_error_rate():
    if total_number_of_requests > 0:
        return (number_of_errors / valid_line_count) * 100
    return 0.0

def suspicious_ip(ip):
    #placeholder
    return False

def print_top_endpoints():
    print("Top 10 Endpoints with Most Traffic:")
    print(f"{'Rank':<6} {'Endpoint':<40} {'Requests':<10}")
    
    for rank, (endpoint, count) in enumerate(top_ten_addresses(), start=1):
        endpoint_display = endpoint[:37] + "..." if len(endpoint) > 40 else endpoint
        print(f"{rank:<6} {endpoint_display:<40} {count:<10}")
    


def print_hourly_traffic(traffic_per_hour):
    max_count = max(traffic_per_hour.values())
    # scale 
    scale = 50 / max_count if max_count > 0 else 0

    for hour in sorted(traffic_per_hour.keys()):
        count = traffic_per_hour[hour]
        bar_length = int(count * scale)
        bar = '█' * bar_length
        print(f"  {hour}:00  | {bar} ({count})")
    print(f"Peak traffic at hour {max(traffic_per_hour, key=traffic_per_hour.get)}:00")
    print(f"Lowest traffic at hour {min(traffic_per_hour, key=traffic_per_hour.get)}:00")

start_time = time.time()
file_path = sys.argv[1]

if file_path.endswith('.gz'):
    file = gzip.open(file_path, 'rt')  # 'rt' = read text mode
else:
    file = open(file_path, 'r')

for i, line in enumerate(file):

    is_valid, data, error = is_valid_log(line)
    total_number_of_requests += 1
    if is_valid: 
        valid_line_count += 1
        timestamp = data['timestamp']
        hour = timestamp.split(':')[1]  
        traffic_per_hour[hour] = traffic_per_hour.get(hour, 0) + 1
        endpoint_handle(data['path'])
        ip_handle(data['ip'])
        number_of_errors += 1 if data['status'].startswith('4') or data['status'].startswith('5') else 0

    else:
        invalid_line_count += 1 

elapsed_time = time.time() - start_time

print (f"Requests : {total_number_of_requests}")
print (f"Valid lines : {valid_line_count}")
print (f"Invalid lines : {invalid_line_count}")
print (f"Unique IP addresses : {len(unique_ip_addresses)}")
print_top_endpoints()
print (f"Error rate : {calculate_error_rate():.2f}%")
print ("Hourly traffic :")
print_hourly_traffic(traffic_per_hour)


file.close()

print(f"Execution time: {elapsed_time:.2f} seconds")
    