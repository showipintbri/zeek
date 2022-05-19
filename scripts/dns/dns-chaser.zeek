module DNS;

export {
	global resolved_names: table[string] of set[addr];
	global temp_table: table[string] of set[string];
	global types: set[string];

	}

event zeek_init()
	{
	types = set("A","AAAA");
	#print (types);
	}

event log_dns(rec: DNS::Info)
	{
	if (rec?$qtype_name == T && rec?$answers == T) {
		if (rec$qtype_name in types) {
			local qry: string = rec$query;
			local ans: vector of string = rec$answers;
			local ans_set: set[string];
			#print (qry);
			#print (ans);
			for (i in ans) {
				add ans_set[ans[i]];
				}
			temp_table[qry] = ans_set;
			}
		}
	}

event zeek_done()
	{
	print (temp_table);
	}
