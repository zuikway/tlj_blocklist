# tlj_blocklist
blocklist generator creates set of ip sets

Based off original Linux Journal article "Server Hardening" in Nov 2015 issue.

This is a modified version for generating ipsets. Original created on large ipset:ip
and could become quite large. It also intermixed ipset:net and ipset:ip types.

This version breaks the ipsets into multiple ipsets and combines
them in ipset:set set of all the ipsets. It preserves the set type
as either ipset:ip or ipset:net.
