# CTF N/W Sniffer

- Still work in progress. Purpose is to sniff according to the ticks of the game. 
- Uses ``swpag_cliet`` and ``tcpdump`` to sync the packet capture. This is relevant as your flags are changing with each tick so you need to sniff and store accordingly.

# Running this Module : 

``sudo python dump_me.py <INTERFACE> -p <PORT> <PORT>`` : For Raw Dump like a cron. Takes a tcp dump of what ever port u feed it. 

``sudo collect_exploits.py <game_interface_url> <auth_token> -i <network_interface> -o <output_directory> ``: A python module that works with Swpag_client to collect TCP dumps according to ticks in the game.

