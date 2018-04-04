# wiresharkReport

Checks IDS for various Scans, DDoS attacks and botnet C&C communications, then produces two reports, a list of labelled connections and a list of labelled hosts on internal network.

Two items need to be run.
1) Scans (using local.rules) with Snort IDS
2) A python script (pCapReport.py) which will create the two repors (connections.txt and hosts.txt).
