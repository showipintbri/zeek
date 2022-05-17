module DNS_HALF;

export {
	global proto_udp: transport_proto = udp;
}

event connection_state_remove(c: connection)
    {
    if (c$conn$proto == proto_udp && c$conn?$service == T && c$conn$service == "dns" && "d" !in c$conn$history) {
    	print ("DNS Query Only!, No Response Seen.");
		}
    }

event zeek_done()
	{
	;
	}
