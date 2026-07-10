# Log Analyzer 

A CLI tool for analyzing log files.
It reads log files line-by-line (handles both plain `.log` and compressed `.gz`), skips malformed lines, and generates useful reports including request counts, unique IPs, top endpoints, error rates, hourly traffic distribution, and suspicious IP detection.

# Requirements 

- Python 3.xx

# Usage 

Supported options : 

file : (Required) Path to the access log file. Supports .log and .gz formats.
--top N	: Number of top endpoints to display (default: 10).
--start "DD/MMM/YYYY:HH:MM:SS" : Filter logs after this timestamp (inclusive).
--end "DD/MMM/YYYY:HH:MM:SS" : Filter logs before this timestamp (inclusive).
--json : Output the report in JSON format instead of human-readable tables.

1. Basic run : 
python main.py access.log

2. Compressed file : 
python main.py access.log.gz

3. Show Top N Endpoints Only : 
python main.py access.log --top N

4. Filter by Time Range : 
python main.py access.log --start "01/Jun/2026:00:00:00" --end "01/Jun/2026:02:00:00"

5. Output to JSON : 
python main.py access.log --json > report.json

* We could also use the HyperLogLog library for handling unique IP addresses without memory issues but it was avoided due to project simplicity.

Output : 
Total requests – Total number of lines processed (valid lines within time range + invalid lines).
Valid lines – Lines that matched the log format and passed the time filter.
Invalid lines – Empty or malformed lines that were skipped.
Unique IP addresses – Count of distinct client IPs.
Top N endpoints – The most frequently requested URL paths, with ranks and request counts.
Error rate (4xx/5xx) – Percentage of requests that returned client or server errors.
Hourly traffic – ASCII histogram showing request volume per hour, plus peak and low hours.
Suspicious IPs – IP addresses with a high proportion of 401 Unauthorized responses (threshold: >30% and at least 10 requests). This helps detect potential brute‑force attacks.
Execution time – Time taken to process the file.

Libraries used : 
re : Pattern-matching and text processing using regular expressions, to match each of the entries.
sys : Access to interpreter variables and functions that interact with the system.
time : Functions for working with time, including measuring execution duration.
gzip : functions to read and write gzip-compressed files, common for archived logs.
argparse : Makes it easy to write user-friendly command-line interfaces by defining arguments, options, and flags.
json : Handles serialization and deserialization.

A problem I encountered during developing the project and how I fixed it : 

One particular problem I encountered was the logic behind computing the total number of requests received. Using the timestamp for giving outputs that lied in a specific time range, happened after the is_valid variable was evaluated because the data['timestamp'] couldn't be null. The original implementation included the total_number_of_requests variable inside the is_valid if block and the invalid lines weren't counting; Also moving the total_number_of_requests count before the if block (and the timestamp) meant that no matter the time interval all lines in the log file were being counted. The way I handled this was processing the timestamp only when is_valid was TRUE and counting the requests after that, while implementing the log output logic in another if block so that the requests outside of the time interval weren't included in the calculations.
Another problem I had was printing the histogram for hourly traffic, which was the fact that without scaling the shapes I got were extremely large and unproportionate, which I handled by scaling the data and printing the scaled bars.

