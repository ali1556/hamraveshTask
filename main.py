import re

invalid_line_count = 0
valid_line_count = 0
total_number_of_requests = 0
unique_ip_addresses = set()
ip_traffic_counts = {}
addresses_with_most_traffic = {}
number_of_errors = 0
error_rate = 0.0
traffic_per_hour = {}


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
    sorted_addresses = sorted(addresses_with_most_traffic.items(), key=lambda x: x[1], reverse=True)
    return sorted_addresses[:10]

def calculate_error_rate():
    if total_number_of_requests > 0:
        return (number_of_errors / total_number_of_requests) * 100
    return 0.0

def suspicious_ip(ip):
    #placeholder
    return False


file = open("access.log", "r")

for i, line in enumerate(file):

    start = 300
    end = 600

    if i<start:
        continue
    if i>=end:
        break

    total_number_of_requests += 1
    is_valid, data, error = is_valid_log(line)

    if is_valid: 
        valid_line_count += 1
        endpoint_handle(data['path'])
        ip_handle(data['ip'])
        number_of_errors += 1 if data['status'].startswith('4') or data['status'].startswith('5') else 0

    else:
        invalid_line_count += 1 


print (f"Requests : {total_number_of_requests}")
print (f"Valid lines : {valid_line_count}")
print (f"Invalid lines : {invalid_line_count}")
print (f"Unique IP addresses : {len(unique_ip_addresses)}")
print (f"Top 10 endpoints with most traffic : {top_ten_addresses()}")
print (f"Error rate : {calculate_error_rate():.2f}%")

file.close()


    