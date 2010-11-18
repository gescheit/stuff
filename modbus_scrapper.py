#!/usr/bin/env python
# -*- coding: utf_8 -*-
import sys
import logging
import time
import modbus_tk
import modbus_tk.defines as cst
import modbus_tk.modbus_tcp as modbus_tcp

logger = modbus_tk.utils.create_logger("console")

if __name__ == "__main__":
    while 1:
        try:
            master_in = modbus_tcp.TcpMaster("192.168.127.254",port=502, timeout_in_sec=5.0)#input
            master_out = modbus_tcp.TcpMaster("192.168.127.253",port=502, timeout_in_sec=5.0)#output
            logger.info("connected")
            while 1:
                in_read=master_in.execute(1, cst.READ_DISCRETE_INPUTS, 0, 16)
                in_read_list=[int(r) for r in in_read]
                logger.info("read %s"%str(in_read_list))#read all register
                out_write=master_out.execute(1, cst.WRITE_MULTIPLE_COILS, 0, output_value=in_read_list)
                logger.info("write %s"%(str(out_write)))#write all register
                time.sleep(5)
                
        except modbus_tk.modbus.ModbusError, e:
            logger.error("%s- Code=%d" % (e, e.get_exception_code()))
        except:
            logger.error("some error")
            