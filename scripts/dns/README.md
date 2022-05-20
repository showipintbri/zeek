# DNS Scripts
Scripts for analyzing DNS traffic.

## dns-chaser.zeek
Correlates the server(resp_h) address with addresses from DNS Answers. This helps identify connections that didn't first have a DNS request. This might indicate hardcoded destination/server addresses. This is sometimes seen in various malware or client applications. This was inspired by an objective from the SANS 503 course.
