#!/bin/bash
# tlj2_blocklist.sh

PATH=$PATH:/sbin
WD=`pwd`
BL_DIR=$WD/bl
IPSET=blset
IPSET_FILE=$WD/blset.sh

if [ ! -d "$BL_DIR" ]; then
  mkdir $BL_DIR
fi

# utility functions
spacer_txt() {
  echo "# --------------------------" >> $IPSET_FILE
}

add_hash_net()
{
  if [ -e "$1" ]; then
    declare in_file="$1"
    declare ip_net="$2"
    spacer_txt
    echo 'echo "Generating hash:net '"$ip_net"'"' >> $IPSET_FILE
    echo "ipset -exist create $ip_net hash:net" >> $IPSET_FILE
    echo "ipset flush " $ip_net >> $IPSET_FILE
    awk  '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0\/[0-9]{1,2}/ { print "ipset -exist add '${ip_net}' " $1;}' $in_file >> $IPSET_FILE
    # add the ipset to the set of ipsets
    echo "ipset add $IPSET " $ip_net >> $IPSET_FILE
    spacer_txt
  fi
}

# assumes hash:net entries have been added to hashnet ipset
# and check to see if hash:ip address already exists before adding
add_hash_ip()
{
  if [ -e "$1" ]; then
    local in_file="$1"
    local ip_ip="$2"
    spacer_txt
    echo 'echo "Generating hash:ip '"$ip_ip"'"' >> $IPSET_FILE
    echo "ipset -exist create $ip_ip hash:ip" >> $IPSET_FILE
    echo "ipset flush " $ip_ip >> $IPSET_FILE
    awk  '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ \
      { print "ipset -q test hashnet "$1" || ipset -exist add '${ip_ip}' " $1";"}' $in_file >> $IPSET_FILE
#      { print "if ipset -q test hashnet "$1"; then ipset -exist add '${ip_ip}' " $1"; fi"}' $in_file >> $IPSET_FILE
    # add the ipset to the set of ipsets
    echo "ipset add $IPSET " $ip_ip >> $IPSET_FILE
    spacer_txt
  fi
}

# ----------------------
# -- block list sites --
# ----------------------
# Project Honey Pot Directory of Dictionary Attacker IPs
honey="http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1"
# TOR Exit Nodes
#torexit="http://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
torexit="https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
# MaxMind GeoIP Anonymous Proxies
#proxies="http://www.maxmind.com/en/anonymous_proxies"
proxies="https://www.maxmind.com/en/proxy-detection-sample-list"
# BruteForceBlocker IP List
bruteforce="http://danger.rulez.sk/projects/bruteforceblocker/blist.php"
# Emerging Threats - Russian Business Networks List
emerging="http://rules.emergingthreats.net/blockrules/rbn-ips.txt"
# Spamhaus Dont Route Or Peer List (DROP)
spamhaus="http://www.spamhaus.org/drop/drop.lasso"
# C.I. Army Malicious IP List
badguys="http://cinsscore.com/list/ci-badguys.txt"
# OpenBLOCK.org 30 day List
openbl="http://www.openbl.org/lists/base.txt"
# Autoshun Shun List
autoshun="http://www.autoshun.org/files/shunlist.csv"
# blocklist.de attackers
attackers="http://lists.blocklist.de/lists/all.txt"

# list of blocklists to include
# put attackers last do to size
#BLIPLIST=( honey torexit proxies bruteforce emerging spamhaus badguys openbl autoshun attackers )
# hash:ip format
BLIPLIST=( honey proxies bruteforce emerging badguys autoshun )
# hash:net format
BLNETLIST=( spamhaus attackers )
#BLIPLIST=( honey )

# list of wizcrafts.net blocklists to include
wizlist="chinese nigerian russian lacnic exploited-servers"

# -----------------------------------
# -- Create the ipset shell script --
# -----------------------------------
echo "Generating ipset '$IPSET' in file '$IPSET_FILE'"
echo "#!/bin/bash" > $IPSET_FILE
echo "# $IPSET_FILE" >> $IPSET_FILE
echo "# Blacklist ipset $IPSET" >> $IPSET_FILE
chmod +x $IPSET_FILE

# Create the hash:set to include the various ipset blocklists
echo "ipset -exist create $IPSET list:set" >> $IPSET_FILE
echo "ipset flush $IPSET" >> $IPSET_FILE

cd $BL_DIR


// create the hashnet list file
echo -n "" > hashnet.tmp

# dshield - add as first ipset hash:net

echo "Getting dshield.org block list"
wget -q -O - http://feeds.dshield.org/block.txt > dshield.bl
#if test -s dshield.tmp; then
#  sort dshield.tmp -n | uniq > dshield.bl
#fi

#if test -s dshield.bl; then
if false; then
  spacer_txt
  echo "# http://feeds.dshield.org/block.txt" >> $IPSET_FILE
  echo 'echo "Generating hash:net dshield"' >> $IPSET_FILE
  echo "ipset -exist create dshield hash:net" >> $IPSET_FILE
  echo "ipset flush dshield" >> $IPSET_FILE
  awk  '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0\t/ { print "ipset -exist add dshield " $1 "/" $3;}' dshield.bl >> $IPSET_FILE
  echo "ipset add $IPSET dshield" >> $IPSET_FILE
  spacer_txt
fi
if test -s dshield.bl; then
  awk  '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0\t/ { print $1 "/" $3;}' dshield.bl >> hashnet.tmp
fi

# get the wizcrafts hash:net lists
for lst in `echo $wizlist`; do
  echo "getting wizcrafts.net $lst"
  wget --quiet http://www.wizcrafts.net/$lst-iptables-blocklist.html
  # check if file empty, if so, use last file
  if test -s $lst-iptables-blocklist.html; then
    grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' $lst-iptables-blocklist.html >  $lst-iptables-blocklist.bl
  fi
  if test -s $lst-iptables-blocklist.bl; then
    cat  $lst-iptables-blocklist.bl >> hashnet.tmp
  fi
done

for lst in ${BLNETLIST[@]}
do
  name=${lst}
  url=${!name}
  echo "Getting list $name from  $url"
  curl "$url" > $name.html
  # test if empty file
  if test -s $name.html; then
    grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' $name.html >> hashnet.tmp
  fi
done

# -----------------------------------------
# create and get the various hash:ip lists
// create the haship list file
echo -n "" > haship.tmp


for lst in ${BLIPLIST[@]}
do
  name=${lst}
  url=${!name}
  echo "Getting list $name from  $url"
  curl "$url" > $name.html
  # test if empty file
  if test -s $name.html; then
    grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' $name.html >> $name.bl
    cat $name.bl >> haship.tmp
  fi
done


# zeus
if false; then # abuse.ch seems down at the moment
  echo "Getting zeustracker.abuse.ch block list"
  wget -q -O - https://zeustracker.abuse.ch/blocklist.php?download=badips > zeus.tmp
  if test -s zeus.tmp; then
    sort zeus.tmp -n | uniq > zeus.bl
  fi
  if test -s zeus.bl; then
    spacer_txt
    echo "# zeustracker.abuse.ch" >> $IPSET_FILE
    echo "ipset -exist create zeus hash:ip" >> $IPSET_FILE
    echo "ipset flush zeus" >> $IPSET_FILE
    awk  '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print "ipset -exist add zeus " $1;}' zeus.bl >> $IPSET_FILE
    echo "ipset add $IPSET zeus" >> $IPSET_FILE
    spacer_txt
  fi
fi

# spamhouse
if false; then
  echo "Getting spamhouse.org drop list and edrop list"
  wget -q -O - http://www.spamhaus.org/drop/drop.txt > drop.tmp
  wget -q -O - http://www.spamhaus.org/drop/edrop.txt > edrop.tmp
  if test -s drop.tmp; then
    mv drop.tmp drop.bl
  fi
  if test -s edrop.tmp; then
    mv edrop.tmp edrop.bl
  fi
  spacer_txt
  echo "# www.spamhouse.org" >> $IPSET_FILE
  add_hash_net drop.bl spamhaus_drop
  add_hash_net edrop.bl spamhaus_edrop
fi

# create the two ipsets for the hash:set
sort hashnet.tmp -n | uniq > hashnet.bl
add_hash_net hashnet.bl hashnet

sort haship.tmp -n | uniq > haship.bl
add_hash_ip haship.bl haship

# cleanup
rm -f *.html
rm -f *.tmp

cd $PWD
# create ipset
#./blset.sh

exit 0

