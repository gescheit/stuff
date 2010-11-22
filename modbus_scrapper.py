#!/usr/bin/env python
# -*- coding: utf_8 -*-
import sys
import logging
import time
import subprocess
import shlex
import modbus_tk
import modbus_tk.defines as cst
import modbus_tk.modbus_tcp as modbus_tcp

zabbix_server="89.207.76.69"
host="moxa_1210"
key_prefix="in."
logger = modbus_tk.utils.create_logger("console")
old_values=[]
inputs=16#input counter
in_slave="192.168.127.254"
out_slave="192.168.127.253"
check = lambda new,old: old != new and [1,new] or [0,new] #compare.first - have or no changes

def zabbix_command(key,value):
    "exec command and return tuple where 0 - stdout,2 exit code"
    command_line="zabbix_sender -z %s -s %s -k %s%s -o %s"%(zabbix_server,host,key_prefix,key,value)
    logger.debug("exec command \"%s\""%(command_line))
    args = shlex.split(command_line)
    p = subprocess.Popen(args,stdout=subprocess.PIPE)
    stdout_value = p.communicate()
    return (stdout_value[0],None,p.returncode)
def zabbix_command_wrapper(value,key):
    print "--",value,key
    if value[0]:#has changes
        return zabbix_command_wrapper(value[1],key)
     
if __name__ == "__main__":
    while 1:
        try:
            master_in = modbus_tcp.TcpMaster(in_slave,port=502, timeout_in_sec=5.0)#input
            master_out = modbus_tcp.TcpMaster(out_slave,port=502, timeout_in_sec=5.0)#output
            logger.info("connected")
            old_values=map(lambda i:0,range(inputs))#default all to 0
            while 1:
                time.sleep(5)
                in_read=master_in.execute(1, cst.READ_DISCRETE_INPUTS, 0, inputs)#read all inputs
                in_read_list=[int(r) for r in in_read]#to list
                compare_list=map(check,in_read_list,old_values)#get diff
                map(zabbix_command_wrapper,compare_list,range(inputs))#give zabbix info about changes
                logger.info("read %s"%str(in_read_list))#read all register
                out_write=master_out.execute(1, cst.WRITE_MULTIPLE_COILS, 0, output_value=in_read_list)
                logger.info("write %s"%(str(out_write)))#write all register
                old_values=in_read_list
        except modbus_tk.modbus.ModbusError, e:
            logger.error("%s- Code=%d" % (e, e.get_exception_code()))
#        except:
#            print "Unexpected error:", sys.exc_info()
#            logger.error("some error")
            