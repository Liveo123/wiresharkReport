import re

# Find the numth ip address and port from the line
def findIPAndPort(line, num):
	addr_port_re = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b')
	addr_re = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
	port_re = re.compile(r'\b:\d{1,5}\b')
	addr_port = addr_port_re.findall(line)[num]
	addr = addr_re.search(addr_port)
	port = port_re.search(addr_port)

	return (addr.group(), port.group()[1:])

# Get the string |addr1|port1|addr2|port2| from the line
def getConnection(line):
	
	addr1, port1 = findIPAndPort(line, 0)
	addr2, port2 = findIPAndPort(line, 1)
	if addr1 > addr2:
		connection = '|' + addr1 + '|' + port1 + '|' + addr2 + '|' + port2 + '|'
	else:
		connection = '|' + addr2 + '|' + port2 + '|' + addr1 + '|' + port1 + '|'
	
	return connection

filepath = '../analysis'

cnt = 0
cncCount = 0
dosCount = 0
scaCount = 0
othCount = 0
hstCnt = 0
botCount = 0
iiCount = 0
benCount = 0
connResults = dict()
hostResults = dict()

# Go through the file and get the cnc addresses	
# If the cnc string is in the line and details to Labels dictionary...
with open(filepath) as fp:

	line = fp.readline()
	while line:
		if line.find('cnc') != -1:
			# Create connections dictionary entries for cnc
			connection = getConnection(line)	
			if connection not in connResults:
				connResults[connection] = 'cnc'
				cnt += 1
				cncCount += 1

			# Create host dictionary entries for cnc
			addr1, port1 = findIPAndPort(line, 0)
			if addr1[0:7] != '192.168':
				addr1, port1 = findIPAndPort(line, 1)
			if addr1 not in hostResults:
				print(addr1 + '|Bot')
				hostResults[addr1] = 'Bot'
				hstCnt += 1
				botCount += 1

		# Get next line in file
		line = fp.readline()

# Go through the file and get the DoS and Scan connecions	
# then add all the uniques with label 'infected whetever' to dictionary
with open(filepath) as fp:

	line = fp.readline()
	while line:
		if line.find('DoS') != -1:
			connection = getConnection(line)	
			if connection not in connResults:
				connResults[connection] = 'infection'
				dosCount += 1
				cnt += 1
			# Create host dictionary entries for Dos (ii)
			addr1, port1 = findIPAndPort(line, 0)
			if addr1[0:7] != '192.168':
				addr1, port1 = findIPAndPort(line, 1)
			if addr1 not in hostResults:
				print(addr1 + '|ii')
				hostResults[addr1] = 'IsolatedInfection'
				hstCnt += 1
				iiCount += 1
		if line.find('Scan') != -1:
			connection = getConnection(line)	
			if connection not in connResults:
				connResults[connection] = 'infection'
				scaCount += 1
				cnt += 1
			# Create host dictionary entries for Scan (ii)
			addr1, port1 = findIPAndPort(line, 0)
			if addr1[0:7] != '192.168':
				addr1, port1 = findIPAndPort(line, 1)
			if addr1 not in hostResults:
				print(addr1 + '|ii')
				hostResults[addr1] = 'IsolatedInfection'
				hstCnt += 1
				iiCount += 1
		# Get next line in file
		line = fp.readline()
				
with open(filepath) as fp:

	line = fp.readline()
	while line:
		if line.find('other') != -1:
			connection = getConnection(line)	
			if connection not in connResults:
				connResults[connection] = 'other'
				cnt += 1
				othCount += 1
			# Create host dictionary entries for benign 
			addr1, port1 = findIPAndPort(line, 0)
			if addr1[0:7] != '192.168':
				addr1, port1 = findIPAndPort(line, 1)
			if addr1 not in hostResults:
				print(addr1 + '|ben')
				hostResults[addr1] = 'Benign'
				hstCnt += 1
				benCount += 1
		# Get next line in file
		line = fp.readline()

# Create a file of all of the connections with their relevant labels
file = open("connections.txt","w+") 
fileCount = 0
for key in connResults:
        file.write(key + connResults[key] + '|' + '\n' )
        fileCount += 1

# Create a dictionary with all of the host hosts with their relevant labels
file = open("hosts.txt","w+")
fileCount = 0
for key in hostResults:
        file.write('|' + key + '|' + hostResults[key] + '|' + '\n' )
        fileCount += 1
# First the cncs




print("cnt = {}".format(cnt))
print("dosCount = {}".format(dosCount))
print("scaCount = {}".format(scaCount))
print("othCount = {}".format(othCount))
print("hstCnt = {}".format(hstCnt))
print("botCount = {}".format(botCount))
print("iiCount = {}".format(iiCount))
print("benCount = {}".format(benCount))
print("fileCount = {}".format(fileCount))
	
	
