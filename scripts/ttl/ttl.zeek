module TTL_COUNT;

export {
    global orig_ttl: table[string] of set[count];
    global resp_ttl: table[string] of set[count];
}

redef record Conn::Info += {
    ## Indicate if the originator of the connection is part of the
    ## "private" address space defined in RFC1918.
orig_ttl: set[count] &optional &log;
resp_ttl: set[count] &optional &log;
};

event new_packet(c: connection, p: pkt_hdr) {
    if (p?$ip == T) {
       	if ( p$ip$src == c$id$orig_h ) {
       		if ( c$uid !in TTL_COUNT::orig_ttl ) {
       			TTL_COUNT::orig_ttl[c$uid] = set(p$ip$ttl);
       			}
       		if ( c$uid in TTL_COUNT::orig_ttl ) {
       			add TTL_COUNT::orig_ttl[c$uid][p$ip$ttl];
       			}
       		}
       	if ( p$ip$src == c$id$resp_h ) {
       		if ( c$uid !in TTL_COUNT::resp_ttl ) {
       			TTL_COUNT::resp_ttl[c$uid] = set(p$ip$ttl);
       			}
       		if ( c$uid in TTL_COUNT::resp_ttl ) {
       			add TTL_COUNT::resp_ttl[c$uid][p$ip$ttl];
       			}
       		}
       	}
    }



event connection_state_remove(c: connection)
    {
    if (c$uid in TTL_COUNT::orig_ttl) {
        c$conn$orig_ttl = TTL_COUNT::orig_ttl[c$uid];
        print (TTL_COUNT::orig_ttl[c$uid]);
    	}
    if (c$uid in TTL_COUNT::resp_ttl) {
        c$conn$resp_ttl = TTL_COUNT::resp_ttl[c$uid];
        print (TTL_COUNT::resp_ttl[c$uid]);
    	}
    }
