import re

file = open("access.log", "r")

# content = file.read()
# print(content)
number_of_lines_read = 0
for line in file:
    parts = line.split()
    for part in parts:
        print(part)
    print(len(parts))
    number_of_lines_read += 1
    if number_of_lines_read >= 2:
        break
file.close()



invalid_line_count = 0
total_number_of_requests = 0
unique_ip_addresses = set()
addresses_with_most_traffic = {}
error_rate = 0
traffic_per_hour = {}

def read_file (file): 
    for line in file:
        line.strip()
        total_number_of_requests += 1
        parts = line.split()
        if len(parts) < 9:
            invalid_line_count += 1
            continue
        ip_address = parts[0]
        unique_ip_addresses.add(ip_address)
        status_code = parts[8]
        if status_code.startswith('4') or status_code.startswith('5'):
            error_rate += 1
        timestamp = parts[3][1:12]  
        if timestamp not in traffic_per_hour:
            traffic_per_hour[timestamp] = 0
        traffic_per_hour[timestamp] += 1
        if ip_address not in addresses_with_most_traffic:
            addresses_with_most_traffic[ip_address] = 0
        addresses_with_most_traffic[ip_address] += 1
    