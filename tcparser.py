import IPy
import re
import time
import shlex
import subprocess
import logging
import socket
import sys
import copy
"""
tc queues parser and "humanaizer".

usage example:
    g=tc()
    print g.qdisc_getall()
    print g.filter_for_class("eth0", "1:10")"""
# TODO: add "ranger" - try summary range of sequences  
# fill ip_p from all matches, not by one
# filter_protocol - bad solution.
#ug_format - format for binary number where some bits can changed. 
#so 0 give 0, 1 give 1, 2 give 0 or 1 
#ip packet format
#name - name
#range - bits in this field
#conjuction - store information about non changeable bits
#format - 0 - raw(in bits), 1 - IP address, 2 - dec number, 3 protocol
                                                            
#you can define this logger in your app in order to see its prints logs  
#LOGGER = logging.getLogger("tcparser")

def get_constants(prefix):
    """Create a dictionary mapping socket module constants to their names."""
    return dict( (getattr(socket, n), n)
                 for n in dir(socket)
                 if n.startswith(prefix)
                 )
protocols = get_constants('IPPROTO_')
filter_protocol = ""
ip_packet_format = [
        {"name": "Version", "range": range(0, 4), "conjunction":[], "format": 0},
        {"name": "Header Length", "range": range(4, 8), "conjunction":[], "format": 0},
        {"name": "DSCP", "range": range(8, 14), "conjunction":[], "format": 0},
        {"name": "ECN", "range": range(14, 16), "conjunction":[], "format": 0},
        {"name": "Total Length", "range": range(16, 32), "conjunction":[], "format": 0},
        {"name": "Identification", "range": range(32, 48), "conjunction":[], "format": 0},
        {"name": "Flags", "range": range(48, 50), "conjunction":[], "format": 0},
        {"name": "Fragment Offset", "range": range(50, 64), "conjunction":[], "format": 0},
        {"name": "TTL", "range": range(64, 72), "conjunction":[], "format": 0},
        {"name": "Protocol", "range": range(72, 80), "conjunction":[], "format": 3},
        {"name": "Header Checksum", "range": range(80, 96), "conjunction":[], "format": 0},
        {"name": "Source IP Address", "range": range(96, 128), "conjunction":[], "format": 1},
        {"name": "Destination IP Address", "range": range(128, 160), "conjunction":[], "format": 1}
                   ]
udp_header = [
        {"name": "Source port", "range": range(0, 16), "conjunction":[], "format": 2},
        {"name": "Destination port", "range": range(16, 32), "conjunction":[], "format": 2},
        {"name": "Length", "range": range(32, 48), "conjunction":[], "format": 2},
         {"name": "Checksum", "range": range(48, 64), "conjunction":[], "format": 2},                     
              ]
tcp_header = [
        {"name": "Source port", "range": range(0, 16), "conjunction":[], "format": 2},
        {"name": "Destination port", "range": range(16, 32), "conjunction":[], "format": 2},
        {"name": "Sequence number", "range": range(32, 64), "conjunction":[], "format": 2},
        {"name": "Acknowledgment number", "range": range(64, 96), "conjunction":[], "format": 2},
        {"name": "Data offset", "range": range(96, 100), "conjunction":[], "format": 2},
        {"name": "Reserved", "range": range(100, 104), "conjunction":[], "format": 2},
        {"name": "CWR", "range": range(104, 105), "conjunction":[], "format": 0},
        {"name": "ECE", "range": range(105, 106), "conjunction":[], "format": 0},
        {"name": "URG", "range": range(106, 107), "conjunction":[], "format": 0},
        {"name": "ACK", "range": range(107, 108), "conjunction":[], "format": 0},
        {"name": "PSH", "range": range(108, 109), "conjunction":[], "format": 0},
        {"name": "RST", "range": range(109, 110), "conjunction":[], "format": 0},
        {"name": "SYN", "range": range(110, 111), "conjunction":[], "format": 0},
        {"name": "FIN", "range": range(111, 112), "conjunction":[], "format": 0},
        {"name": "Window Size", "range": range(112, 128), "conjunction":[], "format": 2},
        {"name": "Checksum", "range": range(128, 144), "conjunction":[], "format": 2},
        {"name": "Urgent pointer", "range": range(144, 160), "conjunction":[], "format": 2},
             ]
unknown_header = [
                  {"name": "unknown_header", "range": range(0, 128), "conjunction":[], "format": 2}
                  ]
class ConsoleHandler(logging.Handler):
    """This class is a LOGGER handler. It prints on the console"""
    
    def __init__(self):
        """Constructor"""
        logging.Handler.__init__(self)
        
    def emit(self, record):
        """format and print the record on the console"""
        print self.format(record)

class LogitHandler(logging.Handler):
    """This class is a LOGGER handler. It send to a udp socket"""
    
    def __init__(self, dest):
        """Constructor"""
        logging.Handler.__init__(self)
        self._dest = dest
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    def emit(self, record):
        """format and send the record over udp"""
        self._sock.sendto(self.format(record)+"\r\n", self._dest)

class DummyHandler(logging.Handler):
    """This class is a LOGGER handler. It doesn't do anything"""

    def __init__(self):
        """Constructor"""
        logging.Handler.__init__(self)

    def emit(self, record): 
        """do nothing with the given record"""
        pass


def create_logger(name="dummy", level=logging.DEBUG, \
                  record_format="%(asctime)s\t%(levelname)s\t%(module)s.%(funcName)s\t%(threadName)s\t%(message)s"):
    """Create a LOGGER according to the given settings"""                                                         
    LOGGER = logging.getLogger("modbus_tk")                                                                       
    LOGGER.setLevel(level)                                                                                        
    formatter = logging.Formatter(record_format)                                                                  
    if name == "udp":                                                                                             
        log_handler = LogitHandler(("127.0.0.1", 1975))                                                           
    elif name == "console":                                                                                       
        log_handler = ConsoleHandler()                                                                            
    elif name == "dummy":                                                                                         
        log_handler = DummyHandler()                                                                              
    else:                                                                                                         
        raise Exception("Unknown handler %s" % name)                                                              
    log_handler.setFormatter(formatter)                                                                           
    LOGGER.addHandler(log_handler)                                                                                
    return LOGGER  


class tc():
    def qdisc_getall(self):
        """Get all queue disciples """
        LOGGER.debug("qdisc_getall()")
        result_list = []
        std_out, std_err, exit_code = self.command("/sbin/tc -d -s qdisc show")
        for lineset in std_out.split("qdisc "):
            if lineset:  # not null
                lines = lineset.split("\n")
                #LOGGER.debug("line=%s" % lines[0])
                type = re.match(r"(?P<qdisc>.*)\ (?P<class>.*)\ dev\ (?P<dev>\w*)\ ", lines[0])
                stat = re.match(r"Sent\ (?P<sent_b>.*)\ (?P<sent_p>.*)\ ", lines[1])
                result_list.append({"dev": type.group("dev"), 
                                    "qdisc": type.group("qdisc"),
                                    "class": type.group("class")})
        return result_list

    def class_info_dev(self, dev):
        "Get queues hierarchy at given dev"
        #type 1 - root
        #type 2 - parent
        dev = str(dev)
        queue_list = []  # list of all queue on this int
        result_list = []  # queue as tree
        #LOGGER.debug("class_info(%s)" % dev)
        std_out, std_err, exit_code = self.command("/sbin/tc -d -s class show dev %s" % dev)
        #LOGGER.debug("result\n %s" % std_out)
        for lineset in std_out.split("class "):
            if lineset:
                lines = lineset.split("\n")
                #LOGGER.debug("line=%s" % lines[0])
                if re.search(r".*root.*", lines[0]):  # root class
                    qclass = re.match(r".*\ (?P<id>[0-9a-fA-F]*\:[0-9a-fA-F]*)\ root\ .*", lines[0]).group("id")
                    parentqclass = 0
                    type = 1  # root
                else:
                    qclass = re.match(r"(htb|sfq)\s(?P<id>[0-9a-fA-F]*\:[0-9a-fA-F]*)\sparent", lines[0]).group("id")
                    parentqclass = re.search(r".*parent\ (?P<id>[0-9a-fA-F]*\:[0-9a-fA-F]*)\ .*", lines[0]).group("id")
                    type = 2  # leaf
                temp_dict = {"class": qclass, "parentqclass": parentqclass, "type": type}
                try:
                    rate = re.search(r".*\ rate\ (?P<rate>.*?)\ .*", lines[0]).group("rate")
                except:
                    rate = 0
                try:
                    ceil = re.match(r".*\ ceil\ (?P<ceil>.*?)\ .*", lines[0]).group("ceil")
                except:
                    ceil = 0
                temp_dict.update({"rate": rate})
                temp_dict.update({"ceil": ceil})
                queue_list.append(temp_dict)
        queue_list = sorted(queue_list, key = lambda k: k['type'])
        print queue_list
        for i in queue_list:
            self.appender(result_list, i)
            #aggregate to hierarchy
            #LOGGER.debug("parse %s" % i)
#            parent_queueqclass = i["parentqclass"]
#            print i
#            
#            if i["type"] == 1:  # root
#                i.update({"data": []})
#                result_list.append(i)
#            else:
#                temp = filter(lambda x: x["class"] == parent_queueqclass, result_list)
#                if temp:
#                    temp[0]["data"].append(i)
        print result_list
        #LOGGER.debug("result_list=%s" % result_list)
        return result_list
    def appender(self, data_list, ins_data):
        if ins_data["type"] == 1: #  root
            data_list.append(ins_data)
        else:
            temp = filter(lambda x: x["class"] == ins_data["parentqclass"], data_list)  # search parent queue
            if temp:
                try:
                    temp[0]["data"]
                except:
                    temp[0].update({"data": []})
                temp[0]["data"].append(ins_data)
            else: # recursion
                for q in data_list:
                    if q["data"]:
                        self.appender(q["data"], ins_data)
                
    def class_stat(self, dev, qclass=None):
        "stat from class on dev. if class not given, show all stat"
#        re_list=[re.compile("rate\s(?P<rate>[\d\w]*)\s.*?", re.S|re.I )]
        result_list = []
        dev = str(dev)
        if qclass:
            std_out, std_err, exit_code = self.command("/sbin/tc -d -s class show dev %s | grep -A 4 -E 'class\ \w*\ %s'" % (dev, re.escape(qclass)))
        else:  # all classes
            std_out, std_err, exit_code = self.command("/sbin/tc -d -s class show dev %s" % (dev))
        std_out = std_out.strip()
        #LOGGER.debug("result\n %s" % std_out)
        for lineset in std_out.split("class "):
            lines = lineset.split("\n")
            if len(lines) > 1:
                temp_dict = {}
                #LOGGER.debug("line=%s" % lines[1])
                q = re.match(r"(?P<qtype>(sfq|htb))\s(?P<id>[0-9a-fA-F]*\:[0-9a-fA-F]*)\s(parent|root)", lines[0])
                qclass = q.group("id")
                qtype = q.group("qtype")
                if qtype=="htb":
                    temp_dict.update({"class": qclass})
                    stat1 = re.match(r".*Sent\s(?P<sent_b>\d*)\sbytes\s(?P<sent_p>\d*)\spkt\s\(dropped\s(?P<dropped>\d*)\,\soverlimits\s(?P<overlimits>\d*)\srequeues\s(?P<requeues>\d*)\).*", lines[1]).groupdict()
                    temp_dict.update(stat1)
                    stat2 = re.match(r".*rate\s(?P<rate_b>\d*\w*)\s(?P<rate_p>\d*\w*)\sbacklog\s(?P<backlog_b>\d*\w*)\s(?P<backlog_p>\d*\w*)\srequeues\s(?P<requeues>\d*)", lines[2]).groupdict()
                    temp_dict.update(stat2)
                else:
                    pass
                #LOGGER.debug("stat1=%s" % stat1)
                #LOGGER.debug("stat2=%s" % stat2)
                result_list.append(temp_dict)
        return result_list


    def filter_for_class(self, dev, qclass):
        "search filter for qclass"
        dev = str(dev)
        result = []
        deferred_matches = []
        filter_protocol = 0
        std_out, std_err, exit_code = self.command("/sbin/tc -d -s filter show dev %s" % (dev))
        spl_line=std_out.split("filter ")
        LOGGER.debug("result\n %s" % spl_line)
        for lineset in spl_line:
            if re.search("\sflowid\s%s\s" % (re.escape(qclass)), lineset, re.I):
                #LOGGER.debug("lineset %s" % lineset)
                for match_str in lineset.split("\n"):
                    if re.search("match\s", match_str, re.I):
                        match_pattern = re.search("match\s(?P<template>[\d\w]*)\/(?P<mask>[\d\w]*)\s*", match_str, re.MULTILINE).groupdict()
                        at = re.search("match.*\sat\s(?P<at>[\d]*)\s.", match_str, re.MULTILINE)
                        nexthdr = re.search("match\s.*\sat\snexthdr\+(?P<nexthdr>\d*)\s.*", match_str, re.MULTILINE)
                        pattern = self.pattern_resolver(value = match_pattern["template"], mask = match_pattern["mask"], bits=32)
                        #check at or nexthdr used
                        if at:
                            at = at.groupdict()["at"]
                            header = ip_packet_format
#                            nexthdr=""
                        elif nexthdr:
                            if filter_protocol == 6:
                                header = tcp_header
                            elif filter_protocol == 17:
                                header = udp_header
                            else:
                                deferred_matches.append(pattern)#unknown protocol
                                
                            nexthdr = nexthdr.groupdict()["nexthdr"]
                            at=nexthdr
#                            else:
#                                nexthdr=""
#                        print "-" * 60, nexthdr
                        oo = self.resolv(pattern, 8 * int(at), header)
                        result.append(oo)
                    for d in deferred_matches:
                        if filter_protocol == 6:
                            header = tcp_header
                            oo = self.resolv(pattern, 8 * int(at), header)
                        elif filter_protocol == 17:
                            header = udp_header
                            oo = self.resolv(pattern, 8 * int(at), header)
                        else:
                            header = unknown_header
                            oo = self.resolv(pattern, 8 * int(at), header)                            
                        result.append(oo)
        return result


    def command(self, command_line):
        "exec command and return tuple where 0 - stdout,2 exit code"
        LOGGER.debug("exec command \"%s\"" % (command_line))
        start = time.time()
        if "|" in command_line:  # pipe
            args = shlex.split(command_line.split("|")[0])
            p = subprocess.Popen(args, stdout = subprocess.PIPE)
            for c in command_line.split("|")[1:]:
                args = shlex.split(c)
                p=subprocess.Popen(args, stdout = subprocess.PIPE, stdin = p.stdout)
        else:
            args = shlex.split(command_line)
            p = subprocess.Popen(args, stdout=subprocess.PIPE)
        stdout_value = p.communicate()
        end = time.time()
        LOGGER.debug("command executed in %ss" % (end - start))
        return (stdout_value[0], None, p.returncode)


    
    def gescho_squirrel(self, x, y):
        """return value in ug_format"""
        #x - value 
        #y - mask
        #truth table
        #    |   x    | 0 | 0 | 1 | 1 | 
        #    |   y    | 0 | 1 | 0 | 1 |
        #    | f(x,y) | 2 | 0 | - | 1 |
        # where 2 - 1 or 0
        x = int(x)
        y = int(y)
        #print x,y
        if x == 0 and y == 0:
            return 2
        elif x == 1 and y == 1:
            return 1
        elif x == 0 and y == 1:
            return 0
        else:
            raise Exception('restricted combination', x, y)
    
    def pattern_resolver(self, value, mask, bits):
        """return list in ug_format.
        mask and value in hex."""
        LOGGER.debug("pattern_resolver('%s','%s','%s')" % (value, mask, bits))
        mask = bin(int(mask, 16))  # bin
        value = bin(int(value, 16)) # bin 
        value = self.formatter(value, bits)
        mask = self.formatter(mask, bits)
#        LOGGER.debug("pattern_resolver() value=%s \nvalue=%s  \nmask=%s" % (value, list(str(value[2:])), list(str(mask[2:]))))
        return map(self.gescho_squirrel, list(str(value)), list(str(mask)))


    def continuity(self, mask):
        """check for continuity
        if yes, return length"""
        mask = mask[::-1]
        l = 0
        for i in range(len(mask)):
            try:
                if mask[i] != "2" and mask[i+1] == "2":  # gap
                    return 0
            except IndexError:
                pass
            if mask[i] == "2":
                l = l + 1
        return l


    def formatter(self,value,length):
        """value - binary 1101010"""
        invert = reduce(lambda x,y: x+"0", range(length), "b1")
        g = bin(int(str(value),2) | int(invert[1:],2))[1:] 
        return str(g[2:])
        
    def resolv(self, pattern, offset, header):
        """return iterator with tuple of human readable field and name of this field
        pattern - list in ug_format
        offset - offset in bits from start of ip packet
        header - header"""
        counter = offset  # start
        ip_p = copy.deepcopy(header)
        for ii in pattern:  # filling ip_packet_format 
            if ii != 2:
                map(lambda i: counter in i["range"] and i["conjunction"].append({"bit": counter, "value": ii}), ip_p)
            counter = counter + 1
        #print ip_p
        for i in ip_p:
            field_name = i["name"]
            field_format = i["format"]
#            print field_name
            if i["conjunction"]:

                field_lenght = len(i["range"])
                start_bit = min(i["range"])
                bit_list = list(reduce(lambda x, y: x + "2", range(field_lenght), ""))  # store information about bits in this filed
                        
                        
                for conj in i["conjunction"]:
                    relative_position = conj["bit"] - start_bit
#                    LOGGER.debug("field_name %s conj[\"bit\"] %s" % (field_name,conj["bit"] ) )
#                    LOGGER.debug("filling %s %s" % (relative_position,  str(conj["value"])))
                    bit_list[relative_position] = str(conj["value"])  # filling unchangeable bits(0 or 1)
#                    LOGGER.debug("filling %s" % bit_list )
                bit_list_str="".join(bit_list)
                if field_format == 1:  # IP
                    l = self.continuity(bit_list_str)
                    #result = IPy.IP(int(result, 2)).__str__()
                    if l:  #  netmask
                        result = bit_list_str[:-l]+"0"*l
                        result =  IPy.IP(int(result, 2)).__str__()
                        yield ("%s/%s" %(result,32-l), field_name)
                        break
                twos_counter = field_lenght - len(i["conjunction"])  # "2" count
                f_range = 2 ** twos_counter  # combination counter
                tmp=0
                for r in range(f_range):  # combination iterator
                    if tmp == 10000:
                        #break
                        pass
                    b_counter = 0  # bit counter 
                    f_counter = 0  # filled bit counter
                    new_bit_list = []
                    f = list(self.formatter(bin(r)[2:], twos_counter))
                    for b in bit_list:
                        if b == "2":
                            new_bit_list.append(f[f_counter])
                            f_counter = f_counter + 1
                        else:
                            new_bit_list.append(bit_list[b_counter])
                        b_counter = b_counter + 1
                        tmp = tmp + 1
                        if tmp == 1000000:
                            #break
                            pass
                    result = "".join(new_bit_list)
                    if field_format == 1:
                        result = IPy.IP(int(result, 2)).__str__()
                    elif field_format == 2:
                        result = int(result, 2)
                    elif field_format==3:
                        result = int(result, 2)
                        try:
                            result = protocols[result].split("_")[1].lower()
                        except:
                            result = result
                    if twos_counter == 0 and field_name == "Protocol":
                        if result == 6: # only tcp
                            filter_protocol = 6
                        if result == 17: # only udp
                            filter_protocol = 17                        
                    yield (result, field_name)



LOGGER = create_logger(name="console", record_format="%(message)s")

#def test():
#    o=pattern_resolver(value="01020300",mask="ffffff00",bits=32)
#    print resolv(o,12*12)
#
#print cProfile.run("test()")
