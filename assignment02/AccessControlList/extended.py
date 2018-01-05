#function for split the content of packets

def split_extended_packet(extended_packet, ip_src_extended, ip_dest_extended, port_extended):
    for line in extended_packet:
        ip_src_extended.append(line.split(' ')[0].split('.'))
        ip_dest_extended.append(line.split(' ')[1].split('.'))
        port_extended.append(line.split(' ')[3].split('.'))

    # print("source ip ")
    # print(ip_src_extended)
    # print("destination ip")
    # print(ip_dest_extended)
    # print("port_extended")
    # print(port_extended)
    return (ip_src_extended, ip_dest_extended, port_extended)

#parse the accesslists, get the source and destination mask and ip and port
def parse_extended_acl(acl_extended, source_mask, destination_mask, source_ip, destination_ip, port_number):
    ip = ['IP']
    for i in range(0, len(acl_extended)):
        if (acl_extended[i][0]) == "access-list":
            # print("####################")
            if (acl_extended[i][1] > '100'):
                if (acl_extended[i][4] != "any"):
                    source_ip.append(acl_extended[i][4].split('.'))
                    source_mask.append(acl_extended[i][5].split('.'))
                    destination_ip.append(acl_extended[i][6].split('.'))
                    destination_mask.append(acl_extended[i][7].split('.'))
                if (acl_extended[i][4] == "any"):
                    source_ip.append(acl_extended[i][4].split())
                    source_mask.append(acl_extended[i][5].split())
                    destination_ip.append(acl_extended[i][4].split())
                    destination_mask.append(acl_extended[i][4].split())
                if (len(acl_extended[i]) == 10):
                    port_number.append(acl_extended[i][9].split())
                if (len(acl_extended[i]) < 10):
                    port_number.append(ip)
    # print("source_mask")
    # print(source_mask)
    # print("destination_mask")
    # print(destination_mask)
    # print("source_ip")
    # print(source_ip)
    # print("destination_ip")
    # print(destination_ip)
    # print("port_number")
    # print(port_number)
    return (acl_extended, source_mask, destination_mask, source_ip, destination_ip, port_number)

#to get the key words,permit or deny if maching
def check_extended(find_source, find_destination):
    for i in range(0, len(acl_extended)):
        if acl_extended[i][0] == "access-list" and len(acl_extended[i]) > 6:
            if (find_source == acl_extended[i][4]) & (find_destination == acl_extended[i][6]):
                if (acl_extended[i][2] == "deny"):
                    return "denied"
                if (acl_extended[i][2] == "permit"):
                    return "permitted"

#check whether there is any in the access list
def check_any():
    for i in range(0, len(acl_extended)):
        if acl_extended[i][0] == "access-list" and len(acl_extended[i]) > 6:
            if ('.'.join(source_mask[i]) == "255.255.255.255"):
                if ('.'.join(source_ip[i]) == "0.0.0.0"):
                    if ('.'.join(destination_mask[i]) == "255.255.255.255"):
                        if '.'.join(destination_ip[i]) == "0.0.0.0":
                            return True
                        else:
                            return False
                    else:
                        return False
                else:
                    return False
        if acl_extended[i][0] == "access-list" and (len(acl_extended[i]) == 6):
            if (acl_extended[i][4] == "any" and acl_extended[i][5] == "any"):
                return True
            else:
                if i != len(acl_extended) - 1:
                    continue
                if i == len(acl_extended) - 1:
                    return False
    return False

#this function is to check protocol
def check_protocol(acl_extended):
    if len(acl_extended)==10:
        if acl_extended[3] == 'TCP':
            if acl_extended[9] == '20' or acl_extended[9] == '21':
                return '20'
            elif acl_extended[9] == '22':
                return '22'
            elif acl_extended[9] == '23':
                return '23'
            elif acl_extended[9] == '80':
                return '80'
        elif acl_extended[3] == 'UDP':
            if acl_extended[9] == '161':
                return '161'
        elif acl_extended[9] == 'IP':
            return 'ANY'
    else:
        return 'ANY'

#this function is to decide whether the packets can match acl, true or false
def extended_result(ip_src_extended, ip_dest_extended, port_extended):
    for i in range(0, len(source_mask)):
        if (len(source_mask[i]) == 4):
            if check_protocol(acl_extended[i]) != 'ANY':
                if len(acl_extended[i]) > 5:
                    if check_protocol(acl_extended[i]) == '20':
                        if port_extended[0] != '20':
                            if port_extended[0] != '21':
                                return False
                        elif port_extended[0] != '21':
                            if port_extended[0] != '20':
                                return False
                    elif port_extended[0] != check_protocol(acl_extended[i]):
                        return False
            for j in range(0, 4):
                if (source_mask[i][j] == '0'):
                    if (source_ip[i][j] != ip_src_extended[j]):
                        return False
                    if (destination_mask[i][j] == '0'):
                        if (destination_ip[i][j] != ip_dest_extended[j]):
                            return False
        return True
    return True

#split access lists into a two dimentional array
with open("extended_file01.txt", "r") as file01:
    extended_data01 = file01.read().split('\n')
acl_extended = []
for line in extended_data01:
    tbl = line.split()
    acl_extended.append(tbl)
# print("acl_extended")
# print(acl_extended)

#get the packet from this file
with open("extended_file02.txt", "r") as file02:
    extended_packet = file02.read().split('\n')
# print("extended_packet")
# print(extended_packet)

#arrays to store the information of packets, source destination port
ip_src_extended = []
ip_dest_extended = []
port_extended = []  # not port number
split_extended_packet(extended_packet, ip_src_extended, ip_dest_extended, port_extended)

source_mask = []
destination_mask = []
source_ip = []
destination_ip = []
port_number = []
parse_extended_acl(acl_extended, source_mask, destination_mask, source_ip, destination_ip, port_number)


# pass packets and print the final results by check extended_outcome, true or false
for i in range(0, len(ip_src_extended)):
    extended_outcome = extended_result(ip_src_extended[i], ip_dest_extended[i], port_extended[i])
    if extended_outcome == True:
        find_source = '.'.join(ip_src_extended[i])
        find_destination = '.'.join(ip_dest_extended[i])
        result = check_extended(find_source,find_destination)
        print(str(find_source)+" " + str(find_destination) + " " + str(result))
    if extended_outcome == False:
        if check_any()==True:
            # print(check_any())
            find_source = '.'.join(ip_src_extended[i])
            find_destination = '.'.join(ip_dest_extended[i])
            print(find_source+" " + find_destination + " " + "permitted")
        else:
            print('.'.join(ip_src_extended[i]) + " " + '.'.join(ip_dest_extended[i]) + " " + "denied")
