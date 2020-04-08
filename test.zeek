global RelationTable :table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value: string) {
	local orig_addr: addr = c$id$orig_h;
	#print orig_addr;
	if (c$http?$user_agent){
		local agents: string = to_lower(c$http$user_agent);
		if (orig_addr in RelationTable) {
			add RelationTable[orig_addr][agents];
		} else {
			RelationTable[orig_addr] = set(agents);
		}
	}
}

event zeek_done() {
	for (orig_addr in RelationTable) {
		if (|RelationTable[orig_addr]| >= 3) {
			print fmt("%s is a proxy",orig_addr);
		}
	}
}
