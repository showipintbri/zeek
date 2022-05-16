# Add Unique TTLs to Conn.log
This script will add a set of TTLs for each originator and responder in the conn.log.

## To Do:
- Create a couple Notice events:
    - If a Connection has more than 3 unique TTLs for any source/dest combination: Notice
    - If a TTL changes from the initial on the return path from any destination
- IPv6 support to include Hop-Limit field as ttl
- Remove entries as they are written to conn.log
- create a way to track TTL's between pair of src/dst regardless of transport protocol or port
    - Raise a Notice if the TTL changes to a number higher than 3
