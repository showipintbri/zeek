module MYTTL;

export {
    global ttl_counts: table[string] of set[count];
}

event new_packet(c: connection, p: pkt_hdr)     {
        if (p?$ip == T) {
                if ( c$uid !in MYTTL::ttl_counts ) {
                        MYTTL::ttl_counts[c$uid] = set(p$ip$ttl);
                        }
                if ( c$uid in MYTTL::ttl_counts ) {
                        add MYTTL::ttl_counts[c$uid][p$ip$ttl];
                        }
                }
        }


event zeek_done() {
#       print (MYTTL::ttl_counts);
        for ( i in MYTTL::ttl_counts ) {
                local abc: count = |MYTTL::ttl_counts[i]|;
                if (abc > 2) {
                        local zyx: string;
                        zyx = "";
                        for ( x in MYTTL::ttl_counts[i]) {
                                zyx += cat(x) + ",";
                                }
                        print fmt("Total Unique: %s, TTLs: %s", |MYTTL::ttl_counts[i]|, zyx);
                        }
                }
        }