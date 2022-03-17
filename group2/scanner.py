from socket import *
import time
import random
import csv
startTime = time.time()

# Constants that can easily be changed to the desired port range
start_port = 1
end_port = 1024
ports = [x for x in range(start_port, end_port+1)]

#make order of ports random by shuffling
random.shuffle(ports)


def make_ip_range():
   '''Makes a list of all IP addresses in our range,
   from 82.148.64.0 to 82.148.79.255'''
   ip_list = []
   ip_base = '82.148'

   for i in range(64, 80):
      for j in range(256):
         ip_list.append(ip_base + '.' + str(i) + '.' + str(j))
   
   return ip_list

# IP range
# 82.148.64.0
# 82.148.79.255

if __name__ == '__main__':
   ip_list = make_ip_range()

   # make csv file to write to
   with open('scan_results.csv', mode='w') as results:
      writer = csv.writer(results, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
      writer.writerow(["Host IP", "Port number scanned", "Timestamp", "Y/N response"])

      # Go through all the ports in the range
      for port in ports:
         random.shuffle(ip_list) # shuffle the IP list so we don't scan IP addresses seqentially
         print ('Starting scan on port: ', port)
         
         # go through all addresses in this range and scan them
         for target in ip_list:
            t_IP = gethostbyname(target)
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(0.01)
            conn = s.connect_ex((t_IP, port))
            if(conn == 0) :   # if we get a response
               print ('Port %d, IP %s: OPEN' % (port,target,))
               response = "Y"
            else: # no response
               response = "N"
            
            writer.writerow([target, port, time.ctime(time.time()), response])

            s.close()

         # sleep for a random time
         time.sleep(0.5+0.01*random.choice(range(1)))
            
print('Time taken:', time.time() - startTime)

# Estimated time to scan is about 9 minutes, we are 0.5 seconds scanning all IPs for each port so (1024*0.5)/60 = 8,5 minutes