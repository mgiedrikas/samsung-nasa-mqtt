import logging
import struct
import socket
import traceback
import threading
import sys
import os
import errno
import signal
import time
import queue
import select
import random
import tools
import loglock
import binascii
from nasa_messages import *

LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
LOGFORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
logging.basicConfig(format=LOGFORMAT)
log = logging.getLogger("nasauart")
log.setLevel(LOGLEVEL)

class PacketGateway:
  #lenbytes: length of the length field prepended to every exchange (rx and tx)
  def __init__(self, host="127.0.0.1", port = 3333, rx_event=None):
    self.host = host
    self.port = port
    self.rx_event = rx_event
    # self.seriallock = threading.RLock()
    self.seriallock = loglock.LogLock("GatewayTxLock")
    self.gatewaysocket = None
    self.queue = queue.Queue()

  def connect(self, host=None, port=None):
    with self.seriallock:
      #log.debug(sys._getframe().f_code.co_name)
      if host:
        self.host = host
      if port:
        self.port = port
      # create an INET, STREAMing socket
      self.gatewaysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # connect to the packet reception socket
      try:
        self.gatewaysocket.connect((self.host, self.port))
        # mark non blocking after connect, to ensure synchronous connect event
        self.gatewaysocket.setblocking(0)
        self.rx=b''
      except:
        traceback.print_exc()

  def start(self):
    threading.Thread(name="packetgateway", target=self._rx_main).start()

  # simple process meant to fetch packets from the gateway and push them to the processing queue
  def _rx_main(self):
    while True:
      try:
        time.sleep(0.25)
        log.debug("reconnecting")
        self.connect()
        while True:
          #fetch some data
          ready, write, exc = select.select([self.gatewaysocket], [], [], 0.1)
          if len(exc) > 0:
            raise BaseException("Data communication issue")

          if not ready or len(ready) == 0 or not ready[0]:
            # go back to select
            continue 

          #thanks python for that GREAT handling of TX that triggers select to return ready set.
          try:
            content = self.gatewaysocket.recv(1024)
          except socket.error as e:
            if e.args[0] == errno.EWOULDBLOCK:
              continue
            raise e

          log.debug("received: " + tools.bin2hex(content))
          # EOF?
          if content == None or len(content) == 0:
            raise BaseException("Data communication issue")

          self.rx += content
          
          # when a packet is completely received (may have received
          # more than one packet at a time, process them all)
          while True:
            # not enough data for a packet
            if len(self.rx) < 1+2:
              break

            log.debug("buffer length= " + hex(len(self.rx)))
            log.debug("buffer " + tools.bin2hex(self.rx))

            fields = struct.unpack_from(">BH", self.rx)

            if fields[0] != 0x32:
              log.debug("invalid prefix, consume it")
              if len(self.rx) > 1:
                self.rx = self.rx[1:]
              continue

            if len(self.rx) < 1 + fields[1] + 1:
              # packet not completely received, wait for more
              break

            # extract packet to be processed
            p = self.rx[:1 + fields[1] + 1]

            if len(p) != 1+fields[1]+1:
              raise BaseException("Invalid encoded length")

            haslock=False
            try:
              self.seriallock.acquire()
              haslock=True
              log.debug("Packet:" + tools.bin2hex(p))

              end = struct.unpack_from(">H", p[-3:])
              if p[-1] != 0x34:
                raise BaseException("Invalid end of packet termination (expected 34)")
              pdata=p[3:-3]
              log.debug("crc computed against "+tools.bin2hex(pdata))
              crc=binascii.crc_hqx(pdata, 0)
              if crc != end[0]:
                raise BaseException("Invalid CRC (expected:"+hex(crc)+", observed:"+hex(end[0])+")")

              # create a queue event for the received packet
              self.seriallock.release()
              haslock=False
              self.rx_event(pdata)
            except:
              traceback.print_exc()
            if haslock:
              self.seriallock.release()
            # consume the enqueued packet
            self.rx = self.rx[len(p):]
      except:
        traceback.print_exc()
        # auto reconnect
        pass


  # Method to send a packet to the HW gateway
  def packet_tx(self, p):
    with self.seriallock:
      # forge packet
      # NOTE: crc excludes SF / TF and length
      crc=binascii.crc_hqx(p, 0)
      # NOTE: include length of CRC(2) and length of length field(2) in the 
      #       total length, exclude SF/TF of total length 
      pp = struct.pack(">BH", 0x32, len(p)+2+2) + p + struct.pack(">HB", crc, 0x34)
      # dump display of sent data
      NasaPacketParser().parse_nasa(p)
      # prepare to wait for ack
      # NOTE: if gateway connection is broken here, then the packet is likely lost.
      try:
        self.gatewaysocket.sendall(pp)
        return True
      except:
        traceback.print_exc()
        return False


NasaPacketTypes = [
  "standby", "normal", "gathering", "install", "download"
]
NasaPayloadTypes = [
  "undef", "read", "write", "request", "notification", "response", "ack", "nack"
]

class NasaPacketParser:
  def __init__(self):
    pass

  """
  Handler parameter is called with severel parameter extracted from the parsed packet
  handler(source, dest, isInfo, protocolVersion, retryCounter, packetType, payloadType, packetNumber, dataSets)
  """
  def parse_nasa(self, p, handler=None):
    if len(p) < 3+3+1+1+1+1:
      raise BaseException("Too short NASA packet")

    log.info(tools.bin2hex(p))

    src = p[0:3]
    dst = p[3:6]
    isInfo = (p[6]&0x80)>>7
    protVersion=(p[6]&0x60)>>5
    retryCnt=(p[6]&0x18)>>3
    rfu=(p[6]&0x7)
    packetType=p[7]>>4
    payloadType=p[7]&0xF
    packetNumber = p[8]
    dsCnt = p[9]

    packetTypStr="unknown"
    if packetType < len(NasaPacketTypes):
      packetTypStr=NasaPacketTypes[packetType]

    payloadTypeStr="unknown"
    if payloadType < len (NasaPayloadTypes):
      payloadTypeStr=NasaPayloadTypes[payloadType]

    log.info("src:"+tools.bin2hex(src)+" dst:"+tools.bin2hex(dst)+" type:"+packetTypStr+" ins:"+payloadTypeStr+" nonce:"+hex(packetNumber))

    ds = []
    off=10
    seenMsgCnt=0
    for i in range(0, dsCnt):
      seenMsgCnt+=1
      kind=(p[off]&0x6)>>1
      if kind == 0:
        s = 1
      elif kind == 1:
        s = 2
      elif kind == 2:
        s = 4
      elif kind == 3:
        if dsCnt != 1:
          raise BaseException("Invalid encoded packet containing a struct: "+tools.bin2hex(p))
        ds.append(["-1", "STRUCTURE", p[off:], tools.bin2hex(p[off:]), p[off:], [p[off:]]])
        break
      messageNumber = struct.unpack(">H",p[off: off+2])[0]
      value = p[off+2:off+2+s]
      valuehex = tools.bin2hex(value)
      valuedec = []
      if s == 1:
        intval = struct.unpack(">b",value)[0]
        valuedec.append(intval)
        if value[0] != 0:
          valuedec.append('ON')
        else:
          valuedec.append('OFF')
      elif s == 2:
        intval = struct.unpack(">h",value)[0]
        valuedec.append(intval)
        valuedec.append(intval/10.0)
      elif s == 4:
        intval = struct.unpack(">i",value)[0]
        valuedec.append(intval)
        valuedec.append(intval/10.0)
      #log.debug(f"  msgnum: {hex(messageNumber)}")
      #log.debug(f"  content: {value}")
      try:
        desc = nasa_message_name(messageNumber)
      except:
        desc = "UNSPECIFIED"
      log.info ("  "+hex(messageNumber)+" ("+desc+"): "+valuehex)
      ds.append([messageNumber, desc, valuehex, value, valuedec])
      off += 2+s

    if seenMsgCnt != dsCnt:
      raise BaseException("Not every message processed")

    if handler is not None:
      handler(source=src, dest=dst, isInfo=isInfo, protocolVersion=protVersion, retryCounter=retryCnt, packetType=packetTypStr, payloadType=payloadTypeStr, packetNumber=packetNumber, dataSets=ds)
    

# testing
if __name__ == '__main__':

  def rx_event(p):
    log.debug("packet received "+ tools.bin2hex(p))


  def rx_event_nasa(p):
    log.debug("packet received "+ tools.bin2hex(p))
    parser.parse_nasa(p)

  pgw = PacketGateway("127.0.0.1", 11223, rx_event=rx_event_nasa)
  parser = NasaPacketParser()

  # build a server
  srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  srv.bind(("127.0.0.1", 11223))
  srv.listen(5)

  pgw.start()

  (sock, address) = srv.accept()

  # send packet from the gw
  assert (pgw.packet_tx(tools.hex2bin('200000b0ffffc014500146062000005206')))
  # read packet
  data = b''
  data = sock.recv(4096)
  assert (len(data) == 1+0x15+1)

  # sock.sendall(tools.hex2bin('320015200000b0ffffc01450014606200000520656e734'))
  # sock.sendall(tools.hex2bin('32003b200000b000ffc014f20d000001020200004061ff412600413f00415001415300415400420300c8420500b74206fe0c420c00bf42170000762734'))
  # sock.sendall(tools.hex2bin("320018510000b0ffffc0143803406f01407601423a00ef69df34"))
  #sock.sendall(tools.hex2bin('320012510000b000ffc014d501020200005ff934'))
  #sock.sendall(tools.hex2bin("320018510000b0ffffc014b803406f0141180142da00ef049534"))
  # sock.sendall(tools.hex2bin("fdfdfdfdfd320018510000b0ffffc014c203406f01407601423a00ef5a8c34fdfdfdfdfd320015200000b0ffffc014b601460620000052064bf834fdf8f9fdfd320039200000b000ffc014b80800000102020000040900000000040a00000000040b00000000040c00000000040d00000000040e00000000d56a34fdfdf9fdfd32003e200000b000ffc014b9080410000000000411012c0000041200320000041302260000041400960000041500500000041600000000041b0020ffff53d8347dfffdfdfb32003e200000b000ffc014ba10400000400101400603402800402900402e004031004043004046004048004060004061ff406500406601406800406900370c34fdfdfdfffd32003e200000b000ffc014bb10406a00406b00406c00406d00406f01407000407400408500408600408700408900408a03408b00409004409100409500489834fdfdfdfffd32003e200000b000ffc014bc10409600409701409900409a05409c0040b10740b20040c40040c500411700411a01411e0041240041250041260041270436c634fdfdfdfdfd32003e200000b000ffc014bd0e412800412900413f00415001415300415400416400416700420100b4420300c8420500b74206fe0c420c00bf42130000f9f134f9fffdfdfd32003e200000b000ffc014be0c421700004229007342350226423600ba42370235423800ba4239fe0c4241fe0c424700be42480000424a00fa424b00a0b72b34fdfdfdfdfa32003e200000b000ffc014bf0c424c0118424d00b4424e02ee424f00fa4250012c425100a0425202bc4253019042690017426a02bc426b000a427300fa76da34fdfdfdfdfb32003e200000b000ffc014c00c4274012c42750096427600a0427700fa427800fa42790096427a0096427b012c427f00b4428b0000428c00fa42ce01e04e3134fdbdfdfd32003c200000b000ffc014c10b42d400c842d600b442d700be42d800f542d900fc42e9000042eb000042ec000042f10000431afe0c440f000000003f4334fdfdfdfdfd320039200000b000ffc014c209441a0032ffce442300000896442400000209442600000000442700005ac980a70080a90080cf0082fe008aa59034bdfdfdfd320024200000b000ffc014c30146041300090040020000200007d900000000000001008b4734bdfdfdfb32001a200000b000ffc014c40284130000000e8414000022a6ffbe34"))
  # sock.sendall(tools.hex2bin("fdfdf9fdfd320012200000b000ffc014a00182fe0085d8a434fdfdfdfdfd320011200000b0ffffc014a301405205815234fdfdfdfdfa320012200000b000ffc014a60182fe0084456434fdfdfddd32003b200000b000ffc014af0d000001020200004061ff412600413f00415001415300415400420300f0420500cd4206fe0c420c00be421700003d3634fdfdfbfdfd32003e200000b000ffc014b00c4236014842370214423801464239fe0c4241fe0c427f00b4428c00e642d4fe0c42d800df42d900fc42e90000431afe0c001f34fdfdfdfdfd320015200000b0ffffc014b101460620000033a9864d34fdfdfdfdfd320029200000b000ffc014b2054426000000004427000082ec80a700841300000030841400003050722f34fdfdfdfdfd320011200000b0ffffc014b80140520569f734fdfdfdfdfd320012200000b000ffc014bc0182fe0082b92434fdfafdfdfd320015200000b0ffffc014c401460620000033a95a5a34fdfdfdfdfd320011200000b0ffffc014ca0140520530f234fdfdfdfdfd320018510000b0ffffc0148e03406f00407601423a00f035bd34320018510000b0ffffc014b803406f0141180142da00ef049534bdfdfdfd320015200000b0ffffc014d501460620000033a9e28734fdfdfdfdfd320011200000b0ffffc014db014052059ef934fdfdfdfdfd320012510000b000ffc01495010202000035e934fdfdfdfdfd320039200000b000ffc014e10800000102020000040900000000040a00000000040b00000000040c00000000040d00000000040e000000003d3c34fdfdbafd32003e200000b000ffc014e2080410000000000411012c0000041200320000041302260000041400960000041500500000041600000000041b0020ffff1cb734fdbdfdfd32003e200000b000ffc014e310400000400101400603402800402900402e004031004043004046004048004060004061ff4065004066014068004069005c8f34fdfdfdfdfd32003e200000b000ffc014e410406a00406b00406c00406d00406f00407000407400408500408600408700408900408a03408b00409004409100409500d20a34fdfbfdfdfd32003e200000b000ffc014e510409600409701409900409a05409c0040b10740b20040c40040c500411700411a01411e004124004125004126004127045d4534fdfdf9fdfd32003e200000b000ffc014e60e412800412900413f00415001415300415400416400416700420100b4420300f0420500cf4206fe0c420c00be42130000d38a34fdfdfd7dff32003e200000b000ffc014e70c4217000042290073423502264236014642370214423801464239fe0c4241fe0c424700be42480000424a00fa424b00a01c5734fdfdfdfdfd32003e200000b000ffc014e80c424c0118424d00b4424e02ee424f00fa4250012c425100a0425202bc4253019042690017426a02bc426b000a427300fae3dd34fdfdfdfdfd32003e200000b000ffc014e90c4274012c42750096427600a0427700fa427800fa42790096427a0096427b012c427f00b4428b0000428c00e642ce01e02e0434fdfdfdfdfd32003c200000b000ffc014ea0b42d4fe0c42d600b442d700be42d800df42d900fa42e9000042eb000042ec000042f10000431afe0c440f00000000637b34fdbdfdfd320039200000b000ffc014eb09441a0032ffce442300000a144424000002764426000000004427000082ec80a70080a90080cf0082fe0082971434fdfdf9fdfd320024200000b000ffc014ec0146041300090040020000200007d9000000000000010026d134fdfdddfd32001a200000b000ffc014ed0284130000002b8414000030500fe234fdfdfdfdfd320015200000b0ffffc014f201460620000033a9f4d034"))
  # sock.sendall(tools.hex2bin("fdfdfdfdfd320011200000b0ffffc01465014052057f6f34fdfdf9fdfd320015200000b0ffffc0147001460620000033a98d0534320018510000b0ffffc014b803406f0141180142da00ef049534fd5dfdfd320039200000b000ffc014720800000102020000040900000000040a00000000040b00000000040c00000000040d00000000040e000000001e8934fdfdf9fdfd32003e200000b000ffc01473080410000000000411012c0000041200320000041302260000041400960000041500500000041600000000041b0020ffff93a934fdfdf9fdfd32003e200000b000ffc0147410400000400101400603402800402900402e004031004043004046004048004060004061ff406500406601406800406900bea534fdfdfdfdfd32003e200000b000ffc0147510406a00406b00406c00406d00406f00407000407400408500408600408700408900408a03408b004090044091004095005d1434fdfdf9fdfd32003e200000b000ffc0147610409600409701409900409a05409c0040b10740b20040c40040c500411700411a01411e00412400412500412600412704f6b734fdfbfdfdfd32003e200000b000ffc014770e412800412900413f00415001415300415400416400416700420100b4420300ef420500cf4206fe0c420c00be42130000b72b34fdfdfdfdfd32003e200000b000ffc014780c4217000042290073423502264236014042370209423801424239fe0c4241fe0c424700be42480000424a00fa424b00a07cd234fdfdfdfdfd32003e200000b000ffc014790c424c0118424d00b4424e02ee424f00fa4250012c425100a0425202bc4253019042690017426a02bc426b000a427300fa6cc334f8fdfdfdfd320012510000b000ffc0141601020200002f2934fdfdb9fd32003e200000b000ffc0147a0c4274012c42750096427600a0427700fa427800fa42790096427a0096427b012c427f00b4428b0000428c00e642ce01e085f634fdfdfdfdfd32003c200000b000ffc0147b0b42d4fe0c42d600b442d700be42d800df42d900f442e9000042eb000042ec000042f10000431afe0c440f000000004c9234fdfdf9fdfd320039200000b000ffc0147c09441a0032ffce442300000a144424000002764426000000004427000082ec80a70080a90080cf0082fe008784eb34fdfdfdfdfd320024200000b000ffc0147d0146041300090040020000200007d90000000000000100735b34fdfdfdfdfd32001a200000b000ffc0147e02841300000003841400003050ee9334fdfdfdfdfd320012200000b000ffc014800182fe0085edac34fdfdfdfdf9320011200000b0ffffc014830140520589e634"))
  # sock.sendall(tools.hex2bin("fdfdfbfdfd320039200000b000ffc014480800000102020000040900000000040a00000000040b00000000040c00000000040d00000000040e00000000c3b634fd5dfdfd32003e320018510000b0ffffc014b803406f0141180142da00ef049534200000b000ffc01449080410000000000411012c000004120032000004130226fefd5dfdfd32003e200000b000ffc01449080410000000000411012c0000041200320000041302260000041400960000041500500000041600000000041b0020ffff7d3634fdfdfdfdfd32003e200000b000ffc0144a320018510000b0ffffc014b803406f0141180142da00ef04953410400000400101400603402800402900402e0040310040f3bdfdfdfd32003e200000b000ffc0144a10400000400101400603402800402900402e004031004043004046004048004060004061ff40650040660140680040690019e2347dfffdfdfd32003e200000b000ffc0144b10406a00406b320018510000b0ffffc014b803406f0141180142da00ef04953400406c00406d00406f00407000407400408500408600408700408900408a0340fffdfbfdfdfd32003e200000b000ffc0144b10406a00406b00406c00406d00406f00407000407400408500408600408700408900408a03408b00409004409100409500fa5334fdfdf9320018510000b0ffffc014b803406f0141180142da00ef049534fdfd32003e200000b000ffc0144c10409600409701409900409a05409c0040b10740b20040c40040c500411700411a01411e00fffdfdfdfdfd32003e200000b000ffc0144c10409600409701409900409a05409c0040b10740b20040c40040c500411700411a01411e00412400412500412600412704182834fdbdfdfd32003e200000b000ffc0144d0e412800412900413f00415001415300415400416400416700420100b4420300ef420500cf4206fe0c420c00be4213000059b434fdfdfafdfd32003e200000b000ffc0144e0c4217000042290073423502264236013d42370200423801424239fe0c4241fe0c424700be42480000424a00fa424b00a07dc734fdfdfdfdfd32003e200000b000ffc0144f0c424c0118424d00b4424e02ee424f00fa4250012c425100a0425202bc4253019042690017426a02bc426b000a427300fa583434fdfdfdfdfd32003e200000b000ffc014500c4274012c42750096427600a0427700fa427800fa42790096427a0096427b012c427f00b4428b0000428c00e642ce01e05c2834fdfdf9fdfd32003c200000b000ffc014510b42d4fe0c42d600b442d700be42d800df42d900f442e9000042eb000042ec000042f10000431afe0c440f00000000312234fdfdfdfdfd320039200000b000ffc0145209441a0032ffce442300000a144424000002764426000000004427000082ec80a70080a90080cf0082fe00858ae434fdfdfdfdfd320024200000b000ffc014530146041300090040020000200007d90000000000000100e9ce34fdfdfdfbfd32001a200000b000ffc0145402841300000002841400003050d69434fd5dfdfd320015200000b0ffffc0145601460620000033a9707134fdfdfdfdfd320012510000b000ffc014970102020000bea934"))

  sock.sendall(tools.hex2bin("fdfdfdfdfd320011200000b0ffffc0341501200102e78134fdfdfdfdfd32001b200000b0ffffc03116030210a2f4200f03040800ffffff8cde34fdfdfdfdfd320015200000b0ffffc03417020210a2f420ff007c6f34fdfdbdfd320018200000b0ffffc0311e02040100ffffff22f80000960e34fdfdfdfdfd320018200000b0ffffc0311f02040300ffffff22f80000531c34fdfdfdfdfd320018200000b0ffffc0312002040100ffffff22f80000df6834fdfdfdfdfd320018200000b0ffffc0312102040100ffffff22f80000dc1d34fdfdfdfdfa32001a200000b0ffffc034220420030220120120150120ff00cb2a34fdfdf9fbfd320011200000b0ffffc02400014052003acd34fdfdfdfdfd320011200000b0ffffc0240101405203a0ff34fdfbfdfdfd320012200000b0ffffc0210201423b0000406c34fde5f9fdfd320015200000b0ffffc024030146062000001a6af35034bdfdfdfd320012200000b0ff50c0210401423b00004d9734fdfdfdfffd320012510000200000c0250401423b5d82f32a34fdfdfdfdfd320011200000b0ffffc0140501200400096434fdfdf9fdfd320011200000b0ffffc0140601405205886134fdfdfdfdfd320012200000b000ffc014070182fe0087d18f34fdfdfdfdfd32002750ffffb0ffffc014000520040104180050e8da0217a2f4041700510000041900500000e34134fdfdfdfdfd32002a20000050e8dac012090620040304180050e8da0217a2f4041700510000041900500000201201941b345dfdfdfd32002a510000200000c015090620040404180050e8da0217a2f4041700510000041900500000201204e10134fd9dfdfd320011200000b0ffffc0140a012004006c9d34fdfdfdfdfd320012510000b0ff50c01105014242ffff01ca34fdfdfdfdfd320012510000b0ff50c01105014242ffff01ca34fdfdfdfdfd320024510000b0ffffc01106040401ffffffff0408ffffffff0402ffffffff4229fffff8b934fdfdfdfdfb320024200000510000c0150604040100200000040800200000040200a0000042290073521934fdfdfd7dff320012510000b0ff50c01105014242ffff01ca34fdfdfdfdfd320015200000b0ffffc014140146062000001a6abc9e34fdfdfdfdfd320012200000b000ffc014150182fe0085600934fdfdfdfdfd320024510000b0ffffc0110c040401ffffffff0408ffffffff0402ffffffff4229ffff3e8634fdfdfdfdfd320024200000510000c0150c04040100200000040800200000040200a0000042290073942634fdfdbdfd32001c510000b0ffffc0110d014604ffffffffffffffffffffffff46a734fdfdfafdfd320024200000510000c0150d0146041300090040020000200007d90000000000000100aac034fdbdfdfd32001a510000b0ffffc0110f010600ffffffffffffffffffff748634fdfdfdf9fd32001a200000510000c0150f01060012300000000000000000d12834fdfdfdfdfd32001a510000b0ffffc01110010601fffffffffffffffffffff15534fdfbfdf9fd32001a200000510000c015100106012001000000000000000038cb345dfdfdfd32001a510000b0ffffc01112010602ffffffffffffffffffff7f6d34fdfdfdfdfd32001a200000510000c0151201060250000000000000000000825134fdfdfdfdfd320011200000b0ffffc0141b01405205ad4134fdfdfdfdfd32003e510000b0ff20c01113104000ff4001ff4065ff4066ff4067ff4068ff4069ff406aff406bff406dff406fff408aff4089ff408bff408cff408eff232234fdfdfd7dff32003e200000510000c0151310400000400101406500406601406700406800406900406a00406b00406d00406f00408a03408900408b00408cff408effba6634fdfdfd7dff32003c510000b0ff20c011150f4085ff4088ff4086ff408dff4090ff4091ff4092ff4046ff406cff4087ff4045ff4081ff402eff4117ff427fffffb31534fdfdfdfdfd32003c200000510000c015150f4085004088ff408600408dff4090044091004092ff404600406c004087004045014081ff402e00411700427f00b4ce3d34fdfdfdfdfd32003e510000b0ff20c011160c4201ffff4235ffff4247ffff4248ffff4203ffff420cffff4236ffff4237ffff4238ffff4239ffff428cffff4246ffffa08f34fdfdfdfdf932003e200000510000c015160c420100b442350226424700be42480000420300e9420c00b8423600b742370142423800b74239fe0c428c00df4246ffff185234fdfdfdfdfd32003e510000b0ff20c01118080409ffffffff040affffffff040bffffffff040cffffffff040dffffffff040effffffff040fffffffff0410ffffffff291f347dfffdfdff32003e200000510000c0151808040900000000040a00000000040b00000000040c00000000040d00000000040e00000000040fffffffff041000000000ae0b34fdbdfdfd32003e510000b0ff20c01119080411ffffffff0412ffffffff0413ffffffff0414ffffffff0416ffffffff441affffffff440fffffffff0448ffffffff7ac134fdfdfbfdfd32003e200000510000c01519080411012c0000041200320000041302260000041400960000041600000000441a0032ffce440f000000000448fffffffff72134fdfdfdfdfd320029510000b0ff20c0111b07411eff42d6ffff42d7ffff42d4ffff42d8ffff42d9ffff42f1ffff16f634fdfbfdf9fd320029200000510000c0151b07411e0042d600b442d700be42d4fe0c42d800dd42d900e342f100008ba8345dfdfdfd320020510000b0ff20c0111c010607ffffffffffffffffffffffffffffffff2d8b34fdfdf9fdfd320020200000510000c0151c010607ffffffffffffffffffffffffffffffff1c1934fdfdfdfffd32001e510000b0ff20c0111e01061fffffffffffffffffffffffffffffee8634fdfdfdfdfd32001e200000510000c0151e01061fffffffffffffffffffffffffffff83e434fdfdfd7dff32003e510000200000c0111f104093ff4094ff4095ff4096ff4097ff4098ff4099ff409aff409bff409cff409dff409eff409fff40a0ff40a1ff40a2ff863234fdfdf9fdfb32003e200000510000c0151f10409301409401409500409600409701409800409900409a05409b01409c00409d00409e00409f0040a00040a10140a200538134fdfdfdfdfd32003c510000200000c011210d40a3ff40a4ff40a5ff40a6ff40a7ff40b4ff424affff424bffff424cffff424dffff424effff424fffff4250ffff8a1a34fdbdfdfd32003c200000510000c015210d40a30040a40040a50040a60140a70040b407424a00fa424b00a0424c0118424d00b4424e02ee424f00fa4250012ce73434fdfdfdfdfd32003e510000200000c011230c4251ffff4252ffff4253ffff4254ffff4255ffff4256ffff4257ffff4258ffff4259ffff425affff425bffff425cffffe41a34fdfdfdfdfd32003e200000510000c015230c425100a0425202bc425301904254ff9c4255009642560190425700fa425801f44259015e425a012c425b0190425c00faa76934fdfdfdfffd32003e510000200000c011250c425dffff425effff425fffff4260ffff4261ffff4262ffff4263ffff4264ffff4265ffff4266ffff4267ffff4268ffff569f34fdfdfdfdfd32003e200000510000c015250c425d00b4425e00b4425f0032426002bc4261001442620032426300054264001e426500b4426600144267000042680064057b34fdfdfdfdfd32003e510000200000c011270c4269ffff426affff426bffff426cffff426dffff426effff426fffff4270ffff4271ffff4272ffff4273ffff4274ffff455534fdbdfdfd32003e200000510000c015270c42690017426a02bc426b000a426c0003426d0000426e01c2426f001442700000427100964272ff6a427300fa4274012c3ef134fdfdfdfdfd320015200000b0ffffc014260146062000001a6a8efb34fdfdfdfdfd32003d510000200000c011290c4275ffff4276ffff4277ffff4278ffff4279ffff427affff427bffff427cffff427dffff427effff4280ffff40c0ff7d1234fdfdf9fdfd32003d200000510000c015290c42750096427600a0427700fa427800fa42790096427a0096427b012c427c0032427d001e427e00034280003240c001a110345dfdfdfd320031510000200000c0112b0a42ceffff4107ff411aff411bff411cff411dff42dbffff42dcffff42ddffff42deffff537534fdfdfdfdfd320031200000510000c0152b0a42ce01e04107ff411a01411b00411c00411d0042db001442dc001442dd001442de003275a234fdfdfdfdfd320024510000200000c0112d064127ff4128ff42edffff42eeffff42efffff42f0ffffa0dc34fdbdfdfd320024200000510000c0152d0641270441280042ed000242ee000242ef000342f000faceaf34fdfd7dfffd320018510000b0ffffc0142f03406f00407601423a00e971d1347dfffdfdfd320011200000b0ffffc0142c01405205c67b34fdfdfdfdfd320012200000b000ffc0142e0182fe0087ac6534fdfdfdfdfd320012200000b000ffc014360182fe00859be134fdfdfdfdfd32003b200000b000ffc014380d000001020200004061ff412600413f00415001415300415400420300e9420500b04206fe0c420c00b842170000f0f834fdfdfdfdff32003e200000b000ffc014390c423600b442370142423800b74239fe0c4241fe0c427f00b4428c00df42d4fe0c42d800dd42d900e342e90000431afe0c07bd34fdfdf9fdfd320029200000b000ffc0143a054426000000004427000082ec80a70084130000000084140000305050ea34fdfdf9fdfd320015200000b0ffffc0143c0146062000001a6a329d34fdfdf9fdfd320011200000b0ffffc0144201405205100f34fdfdfdfdfd320012510000b000ffc0143e0102020000176334"))

  time.sleep(2)
  import signal
  os.kill(os.getpid(), signal.SIGKILL)


