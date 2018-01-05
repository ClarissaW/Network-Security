#find key words if maching, permit or denied
def check_standard(find):
    for i in acl:
        for j in range(len(i)):
            if find == i[j]:
                if(i[j-1]=="deny"):
                    return "denied"
                if(i[j-1]=="permit"):
                    return "permitted"
    return ''

#split packet into two parts, source ip and destination ip
def split_standard_packet(packet,ip_src,ip_dest):
    for i in range(0,len(packet)):
        if i%2==0:
            ip_src.append(packet[i].split('.'))
        else:
            ip_dest.append(packet[i].split('.'))
    return (ip_src,ip_dest)

#check whether the source packet is maching the acclist source address
def standard_result(m,n):
    counter = 0
    for i in range(0,len(mask)):
        if(len(mask[i])==4):
            for j in range(0,4):
                if(mask[i][j]=='0'):
                    if(acc_list[i][j]==m[j]):
                        counter += 1
                    else:
                        counter = 0
                        break
                elif (mask[i][j] == '255'):
                    counter += 1
                if counter == 4:
                    find = '.'.join(acc_list[i])
                    result=check_standard(find)
                    print('.'.join(m) + " " + '.'.join(n) + " " + result)
                    return ''
                    break
                if j==3 & counter < 4:
                    if (('.'.join(mask[i]) == "255.255.255.255") & ('.'.join(acc_list[i]) == "0.0.0.0")):
                        result = '.'.join(m)
                        print(result + " " + '.'.join(n) + " permitted ")
                        return ''
                        break
                else:
                    continue
        elif (mask[i][0]=="any"):
             result =  '.'.join(m)
             print(result + " " + '.'.join(n) + " permit ")
             return ''

        if i==len(mask)-1:
              result = '.'.join(m)
              print(result + " " + '.'.join(n) + " denied")
              return ''

    return ''

#import access list
with open("file01.txt","r") as file01:
    data01 = file01.read().split('\n')
acl = []
for line in data01:
    tbl = line.split()
    acl.append(tbl)

# imoirt packets
with open("file02.txt","r") as file02:
    packet = file02.read().split()
ip_src = []
ip_dest = []
split_standard_packet(packet,ip_src,ip_dest)
acc_list = []
mask = []

#get mask[], which is source mask
for i in range(0,len(acl)):
    if(acl[i][0]) == "access-list":
        if(acl[i][1]<'100'):
            acc_list.append(acl[i][3].split('.'))
            if(acl[i][3]!="any"):
                mask.append(acl[i][4].split('.'))
            if(acl[i][3]=="any"):
                mask.append(acl[i][3].split())

if acl[0][0]=="access-list":
    if acl[0][1]<'100':
        for i in range(0,len(ip_src)):
            final_result = standard_result(ip_src[i],ip_dest[i])
