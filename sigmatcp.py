#!/usr/bin/python

import socket
import time
import os
import sys
import logging
import hashlib

from smbus2 import SMBus, i2c_msg

from threading import Thread

from socketserver import BaseRequestHandler, TCPServer, ThreadingMixIn

COMMAND_READ = 0x0a
COMMAND_READRESPONSE = 0x0b
COMMAND_WRITE = 0x09

HEADER_SIZE = 14
DEFAULT_PORT = 8086
MAX_READ_SIZE = 1024 * 2


def printh(l):
  print([hex(x) for x in l])


class SigmaTCPHandler(BaseRequestHandler):
    def __init__(self, request, client_address, server):
        print("__init__")
        #self.b = SMBus(5)
        BaseRequestHandler.__init__(self, request, client_address, server)

    def setup(self):
        print('setup')

    def finish(self):
        print('finish')

    def handle(self):
        print('handle')
        finished = False
        data = None
        read_more = False

        while not(finished):
            # Read dara
            try:
                buffer = None
                result = None

                if data is None:
                    data = self.request.recv(65536)
                    if len(data) == 0:
                        finished = True
                        continue

                if read_more:
                    print("waiting for more data")
                    d2 = self.request.recv(65536)
                    if (len(d2) == 0):
                        time.sleep(0.1)
                    data = data + d2
                    read_more = False

                # Not an expected header?
                if len(data) > 0 and len(data) < 14:
                    read_more = True
                    continue

                print("received request type {:02X}".format( data[0] ))

                if data[0] == COMMAND_READ:
                    command_length = int.from_bytes(
                        data[1:5], byteorder='big')
                    print('command_length = {}'.format(command_length))

                    print("Len (data, header info): {} {}".format(len(data), command_length))
                    
                    if command_length < len(data):
                        buffer = data[command_length:]
                        data = data[0:command_length]
                        
                    if (command_length > 0) and (len(data) < command_length):
                        read_more = True
                        print("Expect {} bytes from header information (read), but have only {}".format(command_length, len(data)))
                        continue

                    result = self.handle_read(data)

                elif data[0] == COMMAND_WRITE:
                    command_length = int.from_bytes(
                        data[3:7], byteorder='big')
                    print('command_length = {}'.format(command_length))

                    print("Len (data, header info): {} {}".format(len(data), command_length))

                    if command_length < len(data):
                        buffer = data[command_length:]
                        data = data[0:command_length]

                    if (command_length > 0) and (len(data) < command_length):
                        read_more = True
                        print("Expect {} bytes from header information (write), but have only {}".format(command_length, len(data)))
                        continue

                    self.handle_write(data)
                    result = None


                if (result is not None) and (len(result) > 0):
                    print("Sending {} bytes answer to client".format(len(result)))
                    self.request.send(result)

                # Still got data that hasn't been processed?
                if buffer is not None:
                    data = buffer
                else:
                    data = None
                print()

            except ConnectionResetError:
              print('ConnectionResetError')
              finished = True
            except BrokenPipeError:
              print('BrokenPipeError')
              finished = True

    @staticmethod
    def _response_packet(command, addr, data_length):
        packet = bytearray(HEADER_SIZE)
        packet[0] = command
        packet[4] = 14  # header length
        packet[5] = 1  # chip address

        packet[9] = data_length & 0xff
        packet[8] = (data_length >> 8) & 0xff
        packet[7] = (data_length >> 16) & 0xff
        packet[6] = (data_length >> 24) & 0xff

        packet[11] = addr & 0xff
        packet[10] = (addr >> 8) & 0xff

        return packet

    @staticmethod
    def handle_read(data):
        addr = int.from_bytes(data[10:12], byteorder='big')
        length = int.from_bytes(data[6:10], byteorder='big')
        #logging.debug("Handle read %s/%s",addr,length)

        #spi_response = bytes([0x00] * length)
        
        #arr = bytearray()
        #[addr >> 8]
        
        mw = i2c_msg.write(0x38, [(addr >> 8) & 0xFF, addr & 0xFF ])
        mr = i2c_msg.read(0x38, length)
        #print('mw = {}'.format(list(mw)))
        printh(list(mw))
        with SMBus(5) as bus:
          bus.i2c_rdwr(mw, mr)
          #print('mr = {}'.format(list(mr)))
          printh(list(mr))
          spi_response = bytes(list(mr))
        #print('spi_response ({}) = {}'.format(len(spi_response), list(spi_response)))
          
        
        #SigmaTCPHandler.spi.read(addr, length)
        print("read {} bytes from {:04X}".format(length, addr))

        res = SigmaTCPHandler._response_packet(COMMAND_READRESPONSE,
                                               addr,
                                               len(spi_response)) + spi_response
        return res

    @staticmethod
    def handle_write(data):

        if len(data) < 14:
            logging.error("Got incorrect write request, length < 14 bytes")
            return None

        addr = int.from_bytes(data[12:14], byteorder='big')
        length = int.from_bytes(data[8:12], byteorder='big')
        if (length == 0):
            # Client might not implement length correctly and leave
            # it empty
            length = len(data) - 14

        _safeload = data[1]  # TODO: use this

        #if addr == SigmaTCPHandler.dsp.KILLCORE_REGISTER and not(SigmaTCPHandler.updating):
            #logging.debug(
                #"write to KILLCORE seen, guessing something is updating the DSP")
            #SigmaTCPHandler.prepare_update()

        print("writing {} bytes to {:04X}".format(length, addr))
        memdata = data[14:]
        #print(addr)
        #print(memdata)
        
        #mw = i2c_msg.write(0x38, [(addr >> 8) & 0xFF, addr & 0xFF ] + list(memdata))
        #mr = i2c_msg.read(0x38, length)
        #print('mw = {}'.format(list(mw)))
        print( 'LEN memdata = {}   ||||||||  '.format(len(list(memdata))) )
                                                                 #len(list(mw))) )
        
        with SMBus(5) as bus:
          #if len(list(memdata)) <= 4094:
          i = 0
          n = len(memdata) + 2
          block_size = 4094
          mw = i2c_msg.write(0x38, [(addr >> 8) & 0xFF, addr & 0xFF ] + list(memdata[0:block_size]))
          print( 'LEN MW = {}   ||||||||  '.format(len(list(mw))) )
          bus.i2c_rdwr(mw)
          i += block_size
          while i < n:
            mw = i2c_msg.write(0x38, [((addr+i) >> 8) & 0xFF, (addr+i) & 0xFF ] + list(memdata[i:i+block_size]))
            print( 'LEN MW = {}   ||||||||  '.format(len(list(mw))) )
            bus.i2c_rdwr(mw)
            i += block_size
          #bus.i2c_rdwr(mw)
            
        
        
        res = 0
        #SigmaTCPHandler.spi.write(addr, memdata)

        #if addr == SigmaTCPHandler.dsp.HIBERNATE_REGISTER and \
                #SigmaTCPHandler.updating and memdata == b'\00\00':
            #logging.debug(
                #"set HIBERNATE to 0 seen, guessing update is done")
            #SigmaTCPHandler.finish_update()

        return res

class SigmaTCPServer(ThreadingMixIn, TCPServer):

    def __init__(self,
                 server_address=("0.0.0.0", DEFAULT_PORT),
                 RequestHandlerClass=SigmaTCPHandler):
        self.allow_reuse_address = True

        TCPServer.__init__(self, server_address, RequestHandlerClass)

    def server_activate(self):
        TCPServer.server_activate(self)

    def server_close(self):
        TCPServer.server_close(self)


if __name__ == "__main__":
  server = SigmaTCPServer()

  try:
    print("starting TCP server")
    server.serve_forever()
  except KeyboardInterrupt:
    print("aborting ")
    server.server_close()

