import packetgateway
import os
import tools
import logging
import time
import threading 
import argparse
import traceback
import paho.mqtt.client as mqtt
import json

from nasa_messages import *

LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
LOGFORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
logging.basicConfig(format=LOGFORMAT)
log = logging.getLogger("samsung_nasa")
log.setLevel(LOGLEVEL)

def auto_int(x):
  return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument('--mqtt-host', default="192.168.0.4", help="host to connect to the MQTT broker")
parser.add_argument('--mqtt-port', default="1883", type=auto_int, help="port of the MQTT broker")
parser.add_argument('--serial-host', default="127.0.0.1",help="host to connect the serial interface endpoint (i.e. socat /dev/ttyUSB0,parenb,raw,echo=0,b9600,nonblock,min=0 tcp-listen:7001,reuseaddr,fork )")
parser.add_argument('--serial-port', default="7001", type=auto_int, help="port to connect the serial interface endpoint")
parser.add_argument('--nasa-interval', default="30", type=auto_int, help="Interval in seconds to republish MQTT values set from the MQTT side (useful for temperature mainly)")
args = parser.parse_args()

# NASA state
nasa_state = {}
mqtt_client = None
mqtt_published_vars = {}
pgw = None

def nasa_update(msgnum, intval):
  try:
    pub=False
    nasa_name = nasa_message_name(msgnum)
    if not nasa_name in nasa_state:
      pub=True
    else:
      if nasa_state[nasa_name] != intval:
        pub=True
    nasa_state[nasa_name] = intval
    return pub
  except:
    traceback.print_exc()
  return False

class MQTTHandler():
  def __init__(self, mqtt_client, topic, nasa_msgnum):
    self.topic = topic
    self.nasa_msgnum = nasa_msgnum
    self.mqtt_client = mqtt_client

  def publish(self, valueInt):
    self.mqtt_client.publish(self.topic, valueInt)

  def action(self, client, userdata, msg):
    pass

class IntDiv10MQTTHandler(MQTTHandler):
  def publish(self, valueInt):
    self.mqtt_client.publish(self.topic, valueInt/10.0)

  def action(self, client, userdata, msg):
    intval = int(float(msg.payload.decode('utf-8'))*10)
    if nasa_update(self.nasa_msgnum, intval):
      global pgw
      pgw.packet_tx(nasa_set_u16(self.nasa_msgnum, intval))

class IntDiv100MQTTHandler(MQTTHandler):
  def publish(self, valueInt):
    self.mqtt_client.publish(self.topic, valueInt/100.0)

class ONOFFMQTTHandler(MQTTHandler):
  def publish(self, valueInt):
    valueStr = "ON"
    if valueInt==0:
      valueStr="OFF"
    self.mqtt_client.publish(self.topic, valueStr)

class DHWONOFFMQTTHandler(ONOFFMQTTHandler):
  def action(self, client, userdata, msg):
    mqttpayload = msg.payload.decode('utf-8')
    intval=0
    if mqttpayload == "ON":
      intval=1
    if nasa_update(self.nasa_msgnum, intval):
      global pgw
      pgw.packet_tx(nasa_dhw_power(intval == 1))

class COPMQTTHandler(MQTTHandler):
  def publish(self, valueInt):
    self.mqtt_client.publish(self.topic, valueInt)
    # compute COP and publish the value as well
    # round at 2 digits
    self.mqtt_client.publish(self.topic + "_cop", int(nasa_state[nasa_message_name(0x4426)]*100 / valueInt)/100)

class Zone1IntDiv10MQTTHandler(IntDiv10MQTTHandler):
  def action(self, client, userdata, msg):
    global nasa_state
    mqttpayload = msg.payload.decode('utf-8')
    self.mqtt_client.publish(self.topic, mqttpayload)
    new_temp = int(float(mqttpayload)*10)
    if nasa_update(0x423A, new_temp):
      global pgw
      pgw.packet_tx(nasa_set_zone1_temperature(float(mqttpayload)))

class Zone1HOTSwitchMQTTHandler(ONOFFMQTTHandler):
  def action(self, client, userdata, msg):
    mqttpayload = msg.payload.decode('utf-8')
    global pgw
    enabled = mqttpayload == "ON"
    pgw.packet_tx(nasa_zone_power(enabled,1))

class Zone2IntDiv10MQTTHandler(IntDiv10MQTTHandler):
  def action(self, client, userdata, msg):
    global nasa_state
    mqttpayload = msg.payload.decode('utf-8')
    self.mqtt_client.publish(self.topic, mqttpayload)
    new_temp = int(float(mqttpayload)*10)
    if nasa_update(0x42DA, new_temp):
      global pgw
      pgw.packet_tx(nasa_set_zone2_temperature(float(mqttpayload)))
      
class Zone2HOTSwitchMQTTHandler(ONOFFMQTTHandler):
  def action(self, client, userdata, msg):
    mqttpayload = msg.payload.decode('utf-8')
    global pgw
    enabled = mqttpayload == "ON"
    pgw.packet_tx(nasa_zone_power(enabled,2))

#handler(source, dest, isInfo, protocolVersion, retryCounter, packetType, payloadType, packetNumber, dataSets)
def rx_nasa_handler(*args, **kwargs):
  global mqtt_client
  packetType = kwargs["packetType"]
  payloadType = kwargs["payloadType"]
  dataSets = kwargs["dataSets"]
  source = kwargs["source"]
  # ignore non normal packets
  if packetType != "normal":
    return
  # ignore read requests
  if payloadType != "notification" and payloadType != "write":
    return

  for ds in dataSets:
    try:
      # we can tag the master's address
      if ( ds[1] == "NASA_IM_MASTER_NOTIFY" and ds[4][0] == 1) or (ds[1] == "NASA_IM_MASTER" and ds[4][0] == 1):
        nasa_state["master_address"] = source
        break
      # hold the value indexed by its name, for easier update of mqtt stuff
      # (set the int raw value)
      nasa_state[ds[1]] = ds[4][0]

      if ds[1] in mqtt_published_vars:
        # use the topic name and payload formatter from the mqtt publish array
        mqtt_p_v = mqtt_published_vars[ds[1]]
        mqtt_p_v.publish(ds[4][0])
    except:
      traceback.print_exc()

def rx_event_nasa(p):
  log.debug("packet received "+ tools.bin2hex(p))
  parser.parse_nasa(p, rx_nasa_handler)

# once in a while, publish zone2 current temp
def publisher_thread():
  global pgw
  while True:
    time.sleep(args.nasa_interval)
    try:
      # publish zone 1 and 2 values toward nasa (periodic keep alive)
      zone1_temp_name = nasa_message_name(0x423A) # don't use value for the EHS, but from sensors instead
      if zone1_temp_name in nasa_state:
        pgw.packet_tx(nasa_set_zone1_temperature(float(int(nasa_state[zone1_temp_name]))/10))
      zone2_temp_name = nasa_message_name(0x42DA) # don't use value for the EHS, but from sensors instead
      if zone2_temp_name in nasa_state:
        pgw.packet_tx(nasa_set_zone2_temperature(float(int(nasa_state[zone2_temp_name]))/10))
    except:
      traceback.print_exc()

def mqtt_startup_thread():
  global mqtt_client
  def on_connect(client, userdata, flags, rc):
    if rc==0:
      mqtt_setup()
      pass

  mqtt_client = mqtt.Client('samsung_ehs',clean_session=True)
  mqtt_client.on_connect=on_connect
  # initial connect may fail if mqtt server is not running
  # post power outage, it may occur the mqtt server is unreachable until
  # after the current script is executed
  while True:
    try:
      mqtt_client.connect(args.mqtt_host, args.mqtt_port)
      mqtt_client.loop_start()
      mqtt_setup()
      break
    except:
      traceback.print_exc()
    time.sleep(1) 

def mqtt_create_topic(nasa_msgnum, topic_config, device_class, name, topic_state, unit_name, type_handler, topic_set):
  discovery_data={"name": name}
  topic='notopic'
  if topic_set:
    topic=topic_set
    discovery_data["command_topic"] = topic_set
  if topic_state:
    topic=topic_state
    discovery_data["state_topic"] = topic_state
  if device_class:
    discovery_data["device_class"] = device_class
  if unit_name:
    discovery_data["unit_of_measurement"] = unit_name
  mqtt_client.publish(topic_config, 
    payload=json.dumps(discovery_data), 
    retain=True)

  nasa_name = nasa_message_name(nasa_msgnum)
  if not nasa_name in mqtt_published_vars:
    handler = type_handler(mqtt_client, topic, nasa_msgnum)
    mqtt_published_vars[nasa_name] = handler
  
  handler = mqtt_published_vars[nasa_name]
  if topic_set:
    mqtt_client.message_callback_add(topic_set, handler.action)
    mqtt_client.subscribe(topic_set)
  
  return handler

def mqtt_setup():
  mqtt_create_topic(0x4427, 'homeassistant/sensor/samsung_ehs_total_output_power/config', 'energy', 'Samsung EHS Total Output Power', 'homeassistant/sensor/samsung_ehs_total_output_power/state', 'Wh', MQTTHandler, None)
  mqtt_create_topic(0x8414, 'homeassistant/sensor/samsung_ehs_total_input_power/config', 'energy', 'Samsung EHS Total Input Power', 'homeassistant/sensor/samsung_ehs_total_input_power/state', 'Wh', MQTTHandler, None)
  
  mqtt_create_topic(0x4426, 'homeassistant/sensor/samsung_ehs_current_output_power/config', 'energy', 'Samsung EHS Output Power', 'homeassistant/sensor/samsung_ehs_current_output_power/state', 'Wh', MQTTHandler, None)
  mqtt_create_topic(0x8413, 'homeassistant/sensor/samsung_ehs_current_input_power/config', 'energy', 'Samsung EHS Input Power', 'homeassistant/sensor/samsung_ehs_current_input_power/state', 'Wh', COPMQTTHandler, None)
  # special value published by the COPMQTTHandler
  mqtt_client.publish('homeassistant/sensor/samsung_ehs_cop/config', 
    payload=json.dumps({"name": "Samsung EHS Operating COP", 
                        "state_topic": 'homeassistant/sensor/samsung_ehs_current_input_power/state_cop'}), 
    retain=True)

  mqtt_create_topic(0x4236, 'homeassistant/sensor/samsung_ehs_temp_water_in/config', 'temperature', 'Samsung EHS Temp Water In', 'homeassistant/sensor/samsung_ehs_temp_water_in/state', '°C', IntDiv10MQTTHandler, None)
  mqtt_create_topic(0x4238, 'homeassistant/sensor/samsung_ehs_temp_water_out/config', 'temperature', 'Samsung EHS Temp Water Out', 'homeassistant/sensor/samsung_ehs_temp_water_out/state', '°C', IntDiv10MQTTHandler, None)
  mqtt_create_topic(0x420C, 'homeassistant/sensor/samsung_ehs_temp_outer/config', 'temperature', 'Samsung EHS Temp Outer', 'homeassistant/sensor/samsung_ehs_temp_outer/state', '°C', IntDiv10MQTTHandler, None)
  mqtt_create_topic(0x4205, 'homeassistant/sensor/samsung_ehs_temp_eva_in/config', 'temperature', 'Samsung EHS Temp EVA In', 'homeassistant/sensor/samsung_ehs_temp_eva_in/state', '°C', IntDiv10MQTTHandler, None)
  mqtt_create_topic(0x428C, 'homeassistant/sensor/samsung_ehs_temp_mixing_valve_zone1/config', 'temperature', 'Samsung EHS Temp Mixing Valve Zone1', 'homeassistant/sensor/samsung_ehs_temp_mixing_valve_zone1/state', '°C', IntDiv10MQTTHandler, None)
  mqtt_create_topic(0x42E9, 'homeassistant/sensor/samsung_ehs_water_flow/config', 'volume_flow_rate', 'Samsung EHS Water Flow', 'homeassistant/sensor/samsung_ehs_water_flow/state', 'L/min', IntDiv10MQTTHandler, None)
  mqtt_create_topic(0x4028, 'homeassistant/binary_sensor/samsung_ehs_op/config', 'running', 'Samsung EHS Operating', 'homeassistant/binary_sensor/samsung_ehs_op/state', None, ONOFFMQTTHandler, None)
  mqtt_create_topic(0x402E, 'homeassistant/binary_sensor/samsung_ehs_defrosting_op/config', 'running', 'Samsung EHS Defrosting', 'homeassistant/binary_sensor/samsung_ehs_defrosting_op/state', None, ONOFFMQTTHandler, None)
  mqtt_create_topic(0x82FE, 'homeassistant/sensor/samsung_ehs_water_pressure/config', 'pressure', 'Samsung EHS Water Pressure', 'homeassistant/sensor/samsung_ehs_water_pressure/state', 'bar', IntDiv100MQTTHandler, None)
  
  mqtt_create_topic(0x4000, 'homeassistant/switch/samsung_ehs_zone1/config', None, 'Samsung EHS Zone1', 'homeassistant/switch/samsung_ehs_zone1/state', None, Zone1HOTSwitchMQTTHandler, 'homeassistant/switch/samsung_ehs_zone1/set')
  mqtt_create_topic(0x4201, 'homeassistant/number/samsung_ehs_temp_zone1_target/config', 'temperature', 'Samsung EHS Temp Zone1 Target', 'homeassistant/number/samsung_ehs_temp_zone1_target/state', '°C', IntDiv10MQTTHandler, 'homeassistant/number/samsung_ehs_temp_zone1_target/set')
  #mqtt_create_topic(0x4203, 'homeassistant/sensor/samsung_ehs_temp_zone1_current/config', 'temperature', 'Samsung EHS Temp Zone1 Current', 'homeassistant/sensor/samsung_ehs_temp_zone1_current/state', '°C', IntDiv10MQTTHandler, None)
  mqtt_create_topic(0x423A, 'homeassistant/number/samsung_ehs_temp_zone1/config', 'temperature', 'Samsung EHS Temp Zone1', 'homeassistant/sensor/samsung_ehs_temp_zone1/state', '°C', Zone1IntDiv10MQTTHandler, 'homeassistant/number/samsung_ehs_temp_zone1/set')
  mqtt_create_topic(0x42D8, 'homeassistant/sensor/samsung_ehs_temp_outlet_zone1/config', 'temperature', 'Samsung EHS Temp Outlet Zone1', 'homeassistant/sensor/samsung_ehs_temp_outlet_zone1/state', '°C', IntDiv10MQTTHandler, None)
  
  mqtt_create_topic(0x411e, 'homeassistant/switch/samsung_ehs_zone2/config', None, 'Samsung EHS Zone2', 'homeassistant/switch/samsung_ehs_zone2/state', None, Zone2HOTSwitchMQTTHandler, 'homeassistant/switch/samsung_ehs_zone2/set')
  mqtt_create_topic(0x42D6, 'homeassistant/number/samsung_ehs_temp_zone2_target/config', 'temperature', 'Samsung EHS Temp Zone2 Target', 'homeassistant/number/samsung_ehs_temp_zone2_target/state', '°C', IntDiv10MQTTHandler, 'homeassistant/number/samsung_ehs_temp_zone2_target/set')
  #mqtt_create_topic(0x42D4, 'homeassistant/sensor/samsung_ehs_temp_zone2_current/config', 'temperature', 'Samsung EHS Temp Zone2 Current', 'homeassistant/sensor/samsung_ehs_temp_zone2_current/state', '°C', IntDiv10MQTTHandler, None)
  mqtt_create_topic(0x42DA, 'homeassistant/number/samsung_ehs_temp_zone2/config', 'temperature', 'Samsung EHS Temp Zone2', 'homeassistant/number/samsung_ehs_temp_zone2/state', '°C', Zone2IntDiv10MQTTHandler, 'homeassistant/number/samsung_ehs_temp_zone2/set')
  mqtt_create_topic(0x42D9, 'homeassistant/sensor/samsung_ehs_temp_outlet_zone2/config', 'temperature', 'Samsung EHS Temp Outlet Zone2', 'homeassistant/sensor/samsung_ehs_temp_outlet_zone2/state', '°C', IntDiv10MQTTHandler, None)

  mqtt_create_topic(0x4065, 'homeassistant/switch/samsung_ehs_dhw_op/config', None, 'Samsung EHS DHW Operating', 'homeassistant/switch/samsung_ehs_dhw_op/state', '', DHWONOFFMQTTHandler, 'homeassistant/switch/samsung_ehs_dhw_op/set')
  mqtt_create_topic(0x4237, 'homeassistant/sensor/samsung_ehs_temp_dhw/config', 'temperature', 'Samsung EHS Temp DHW Tank', 'homeassistant/sensor/samsung_ehs_temp_dhw/state', '°C', IntDiv10MQTTHandler, None)


threading.Thread(name="publisher", target=publisher_thread).start()
threading.Thread(name="mqtt_startup", target=mqtt_startup_thread).start()

#todo: make that parametrized
pgw = packetgateway.PacketGateway(args.serial_host, args.serial_port, rx_event=rx_event_nasa)
parser = packetgateway.NasaPacketParser()
pgw.start()
