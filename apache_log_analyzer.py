"""
DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.

Copyright (c) 2025 Ricardo Cescon - https://cescon.de and/or its affiliates. All rights reserved.

The contents of this file are subject to the terms of
Common Development and Distribution License("CDDL") (collectively, the "License").  You
may not use this file except in compliance with the License.  You can
obtain a copy of the License at
https://oss.oracle.com/licenses/CDDL-1.1
or CDDL-1.1.txt OR LICENSE.txt.  See the License for the specific
language governing permissions and limitations under the License.

When distributing the software, include this License Header Notice in each
file and include the License file at CDDL-1.1.txt OR LICENSE.txt.

Modifications:
If applicable, add the following below the License Header, with the fields
enclosed by brackets [] replaced by your own identifying information:
"Portions Copyright [year] [name of copyright owner]"

"""

import datetime
import argparse


def parse_webserver_log(log_file, start_time, end_time):
    """
    parse Apache access logs for suspicious traffic within a specified time range.
    """
    try:
        with open(log_file, "r") as f:
            log_lines = f.readlines()

        relevant_logs = []
        for line in log_lines:
            try:
                timestamp_str = line.split("[")[1].split("]")[0]
                log_time = datetime.datetime.strptime(
                    timestamp_str, "%d/%b/%Y:%H:%M:%S %z"
                )

                if start_time <= log_time <= end_time:
                    relevant_logs.append(line.strip())
            except (IndexError, ValueError) as e:
                print(
                    f"Warning: Could not parse timestamp from log line: {line}. Error: {e}"
                )
        return relevant_logs

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def analyze_traffic(log_lines, suspicious_count):
    """Analyzes the relevant log lines for potential bot activity."""
    if not log_lines:
        print("No relevant log lines found.")
        return

    ip_counts = {}
    user_agent_counts = {}
    request_counts = {}
    http_error_counts = {}

    for line in log_lines:
        try:
            ip_address = line.split(" ")[0].split(",")[0]
            user_agent = line.split('"')[-2]
            request = line.split('"')[1]
            http_error = line.split('"')[-5].strip().split(" ")[0]

            ip_counts[ip_address] = ip_counts.get(ip_address, 0) + 1
            http_error_counts[http_error] = http_error_counts.get(http_error, 0) + 1
            user_agent_counts[user_agent] = user_agent_counts.get(user_agent, 0) + 1
            request_counts[request] = request_counts.get(request, 0) + 1

        except IndexError:
            print(f"Warning: Could not extract data from log line: {line}")

    print("\nIP Address Counts:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")

    print("\nHTTP Error Counts:")
    for http_error, count in http_error_counts.items():
        print(f"{http_error}: {count}")

    print("\nUser-Agent Counts:")
    for user_agent, count in user_agent_counts.items():
        print(f"{user_agent}: {count}")

    print("\nRequest Counts:")
    for request, count in request_counts.items():
        print(f"{request}: {count}")

    suspicious_ips = [ip for ip, count in ip_counts.items() if count > suspicious_count]
    if suspicious_ips:
        print(
            f"\nSuspicious IPs (more than {suspicious_count} requests): {suspicious_ips}"
        )
    else:
        print("\nNo suspicious IPs detected based on request counts.")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Analyze Apache access logs for bot activity.",
        epilog="Example: python3 %(prog)s /var/log/apache2/access.log '2025-04-16 06:45:00 +0000' '2025-04-16 07:15:00 +0000'",
    )
    parser.add_argument("log_file", help="Path to the Apache access log file.")
    parser.add_argument("start_time", help="Start time (YYYY-MM-DD HH:MM:SS +ZZZZ).")
    parser.add_argument("end_time", help="End time (YYYY-MM-DD HH:MM:SS +ZZZZ).")
    parser.add_argument(
        "--suspicious_count",
        help="if the IP address has more than this number of requests, it will be considered suspicious",
        type=int,
        default=10,
        required=False,
    )

    args = parser.parse_args()

    try:
        start_time = datetime.datetime.strptime(args.start_time, "%Y-%m-%d %H:%M:%S %z")
        end_time = datetime.datetime.strptime(args.end_time, "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        print("Error: Invalid time format. Please use YYYY-MM-DD HH:MM:SS +ZZZZ.")
        exit(1)

    log_lines = parse_webserver_log(args.log_file, start_time, end_time)

    if log_lines is not None:
        analyze_traffic(log_lines, args.suspicious_count)
