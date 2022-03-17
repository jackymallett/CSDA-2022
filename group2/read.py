from socket import *
import time
import random
import csv

PORTS = [x for x in range(2049, 65535)]

def read_in_open_Ip():
    dict_t = {}
    with open('scan_results2.csv') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line[-1] == "Y":
                new_list = line.split(',')
                target = new_list[0]
                dict_t[target] = dict_t.get(target, [])+[new_list[1]]            
    return dict_t

def scan(dict_t, counter):
     # Go through all the ports in the range
    ports = PORTS[counter-1000:counter]
    random.shuffle(ports)
    for port in ports:
        print ('Starting scan on port: ', port)
        
        # go through all addresses in this range and scan them
        for target in dict_t.keys():
            t_IP = gethostbyname(target)
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(0.01)
            conn = s.connect_ex((t_IP, port))
            if(conn == 0) :   # if we get a response
                print ('Port %d, IP %s: OPEN' % (port,target,))
                dict_t[target] = dict_t.get(target, [])+[port]            
            
            

            s.close()

        # sleep for a random time
        time.sleep(0.5+0.01*random.choice(range(1)))
    return dict_t

def write_dict(dict_t):
    with open('open.csv', mode='w') as results:
        writer = csv.writer(results, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["Host IP", "Port number scanned"])

        i = 0
        for target, ports in dict_t.items():
            print(i,target, ports)
            i += 1
            writer.writerow([target, ports])   


if __name__ == '__main__':
    dict_t = read_in_open_Ip()

    counter = 1000
    while counter < 63000:
        dict_t = scan(dict_t, counter)
        write_dict(dict_t)
        counter += 1000
        print(counter)
        
    # make csv file to write to
