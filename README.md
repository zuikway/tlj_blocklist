# tlj_blocklist
blocklist generator creates set of ip sets

Based off original Linux Journal article "Server Hardening" in Nov 2015 issue.

This is a modified version for generating ipsets. The original proposed script
created a large ipset hash:ip and could become quite large.
It also intermixed hash:net and hash:ip types.

This version breaks the ipsets into two ipsets and combines
them in a ipset hash:set set of the two ipsets. It preserves the set type
as either hash:ip or hash:net.

The script downloads the various blocklists and generates a script
"blset.sh" which creates the actual ipset hash:set that includes
ipset hashnet a hash:net and ipset haship a hash:ip.

Running the generate blset.sh script creates the ipset blset which can be used
in iptables, or in a shorewall rules file.

Example shorewall rules entry:

DROP:$LOG    net:+blset      all

DROP:$LOG    all             net:+blset

