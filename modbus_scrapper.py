#!/usr/bin/env python
# -*- coding: utf_8 -*-
import sys
import os
import logging
import time
import subprocess
import shlex
import modbus_tk
import modbus_tk.defines as cst
import modbus_tk.modbus_tcp as modbus_tcp

debug=1

logger = modbus_tk.utils.create_logger("console")
inputs=16#input counter
in_slave="192.168.127.254"#moxa 1210
out_slave="192.168.127.253"#moxa 1211
sleep=5#sleep 

zabbix_mode=1#if use zabbix_sender
zabbix_server=""
host="moxa_1210"
key_prefix="in."

if debug:
    import traceback
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.DEBUG)
old_values=[]
check = lambda new,old: old != new and [1,new] or [0,new] #compare.first - have or no changes

def daemonize (stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    # Perform first fork.
    try:
        pid = os.fork( )
        if pid > 0:
            sys.exit(0) # Exit first parent.
    except OSError, e:
        sys.stderr.write("fork #1 failed: (%d) %sn" % (e.errno, e.strerror))
        sys.exit(1)
    # Decouple from parent environment.
    os.chdir("/")
    os.umask(0)
    os.setsid( )
    # Perform second fork.
    try:
        pid = os.fork( )
        if pid > 0:
            sys.exit(0) # Exit second parent.
    except OSError, e:
        sys.stderr.write("fork #2 failed: (%d) %sn" % (e.errno, e.strerror))
        sys.exit(1)
    # The process is now daemonized, redirect standard file descriptors.
    for f in sys.stdout, sys.stderr: f.flush( )
    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    os.dup2(si.fileno( ), sys.stdin.fileno( ))
    os.dup2(so.fileno( ), sys.stdout.fileno( ))
    os.dup2(se.fileno( ), sys.stderr.fileno( ))

def zabbix_command(key,value):
    "exec command and return tuple where 0 - stdout,2 exit code"
    command_line="zabbix_sender -z %s -s %s -k %s%s -o %s"%(zabbix_server,host,key_prefix,key,value)
    logger.debug("exec command \"%s\""%(command_line))
    args = shlex.split(command_line)
    p = subprocess.Popen(args,stdout=subprocess.PIPE)
    stdout_value = p.communicate()
    logger.debug("zabbix sender result=%s"%stdout_value[0])
    return (stdout_value[0],None,p.returncode)
def zabbix_command_wrapper(value,key):
    logger.debug("zabbix_command_wrapper() value=%s ,key=%s"%(value,key))
    if value[0]:#has changes
        return zabbix_command(key,value[1])

daemonize()


while 1:
    try:
        master_in = modbus_tcp.TcpMaster(in_slave,port=502, timeout_in_sec=10.0)#input
        master_out = modbus_tcp.TcpMaster(out_slave,port=502, timeout_in_sec=10.0)#output
        logger.info("connected")
        if zabbix_mode:
            old_values=map(lambda i:0,range(inputs))#default all to 0
            map(zabbix_command,range(inputs),old_values)
        while 1:
            time.sleep(sleep)
            in_read=master_in.execute(1, cst.READ_DISCRETE_INPUTS, 0, inputs)#read all inputs
            if zabbix_mode:
                in_read_list=[int(r) for r in in_read]#to list
                compare_list=map(check,in_read_list,old_values)#get diff
                logger.debug("compare_list=%s" % compare_list)
                logger.debug("range(inputs)=%s" % range(inputs))
                map(zabbix_command_wrapper,compare_list,range(inputs))#give zabbix info about changes
            logger.debug("read %s"%str(in_read_list))#read all register
            out_write=master_out.execute(1, cst.WRITE_MULTIPLE_COILS, 0, output_value=in_read_list)
            logger.debug("write %s"%(str(out_write)))#write all register
            old_values=in_read_list
    except modbus_tk.modbus.ModbusError, e:
        logger.error("%s- Code=%d" % (e, e.get_exception_code()))
    except:
        if debug:
            logger.debug("traceback %s "%(traceback.print_exc()))
        logger.error("some error %s %s %s"%(sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2]))
        
