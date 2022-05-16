module TTL_COUNT;

export {
    global orig_ttl: table[string] of set[count];
    global resp_ttl: table[string] of set[count];
    type tuple: record {
    	orig: addr &log;
    	resp: addr &log;
    	};
    global ttl_tuple: table[tuple] of set[count];
}

redef record Conn::Info += {
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
#        print (TTL_COUNT::orig_ttl[c$uid]);
    	}
    if (c$uid in TTL_COUNT::resp_ttl ) {
        c$conn$resp_ttl = TTL_COUNT::resp_ttl[c$uid];
#        print (TTL_COUNT::resp_ttl[c$uid]);
    	}


    local src_dst_pair: tuple = [$orig=c$id$orig_h, $resp=c$id$resp_h];
	if (src_dst_pair in TTL_COUNT::ttl_tuple) {
		;
		}
	if (src_dst_pair !in TTL_COUNT::ttl_tuple) {
#		print(src_dst_pair);
#		TTL_COUNT::ttl_tuple[src_dst_pair] = TTL_COUNT::orig_ttl[c$uid];
		if (c$uid in TTL_COUNT::resp_ttl ) {
			TTL_COUNT::ttl_tuple[src_dst_pair] = (TTL_COUNT::orig_ttl[c$uid] | TTL_COUNT::resp_ttl[c$uid]);
			}
		if (c$uid !in TTL_COUNT::resp_ttl ) {
			TTL_COUNT::ttl_tuple[src_dst_pair] = TTL_COUNT::orig_ttl[c$uid];
			}
		}
#	print (TTL_COUNT::ttl_tuple);
	for (i in TTL_COUNT::ttl_tuple) {
		if (|TTL_COUNT::ttl_tuple[i]| > 2) {
			print (i);
			print ("Greater than 2 TTL values");
			}
		
		}
	}
