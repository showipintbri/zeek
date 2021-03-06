module DNS;

export {
	global resolved_names: table[string] of set[addr];
	global types: set[string];
	}
	
redef record Conn::Info += {
    dns_seen: bool &optional &log;
};

event zeek_init()
	{
	types = set("A","AAAA");
	}

event log_dns(rec: DNS::Info)
	{
	if (rec?$qtype_name == T && rec?$answers == T) {
		if (rec$qtype_name in types) {
			local qry: string = rec$query;
			local ans: vector of string = rec$answers;
			local address_set: set[addr];
			#print (qry);
			#print (ans);
			for (i in ans) {
				if (is_valid_ip(ans[i]) == T) {
					local str_to_addr: addr = to_addr(ans[i]);
					add address_set[str_to_addr];
					}
				}
			if (qry !in resolved_names) {
				resolved_names[qry] = address_set;
				#print(resolved_names);
				}
			else
				{
				for (y in resolved_names[qry]) {
					#print (y);
					add address_set[y];
					}
				resolved_names[qry] = address_set;
				}
			}
		}
	}
	
event connection_state_remove(c: connection)
	{
	for (i in resolved_names) {
		for (x in resolved_names[i]) {
			if (c$id$resp_h == x) {
				c$conn$dns_seen = T;
				}
			}
		}
	}

event zeek_done()
	{
	print (resolved_names);
	}
