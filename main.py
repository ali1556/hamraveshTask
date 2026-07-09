import re

invalid_line_count = 0
valid_count = 0
total_number_of_requests = 0
unique_ip_addresses = set()
addresses_with_most_traffic = {}
error_rate = 0
number_of_errors = 0
traffic_per_hour = {}


log_pattern = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^"]+) HTTP/\d\.\d" (?P<status>\d{3}) (?P<bytes>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$'
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

file = open("access.log", "r")

for i, line in enumerate(file):
    if i>=1000:
        break
    is_valid, data, error = is_valid_log(line)
    total_number_of_requests += 1
    if is_valid: 
        valid_count += 1
        unique_ip_addresses.add(data['ip'])
        endpoint_handle(data['path'])
        number_of_errors += 1 if data['status'].startswith('4') or data['status'].startswith('5') else 0

    else:
        invalid_line_count += 1
        print(f"invalid entry number : {i}")
        print(f"Invalid entry: {error}")
        print(f"Line: {line.strip()}")

file.close()


    