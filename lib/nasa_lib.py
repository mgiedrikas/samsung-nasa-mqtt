from enum import Enum
from typing import Union, List


class MessageSetType(Enum):
    ENUM = 0
    VARIABLE = 1
    LONG_VARIABLE = 2
    STRUCTURE = 3


class MessageNumber(Enum):
    NASA_IM_MASTER_NOTIFY = 0x0000
    NASA_INSPECTION_MODE = 0x0004
    NASA_GATHER_INFORMATION = 0x0007
    NASA_GATHER_INFORMATION_COUNT = 0x0008
    NASA_ENABLEDOWNLOAD = 0x000A
    NASA_DETECTION_TYPE = 0x000D
    NASA_PEAK_LEVEL = 0x000E
    NASA_PEAK_MODE = 0x000F
    NASA_PEAK_CONTROL_PERIOD = 0x0010
    NASA_POWER_MANUFACTURE = 0x0011
    NASA_POWER_CHANNEL1_TYPE = 0x0012
    NASA_POWER_CHANNEL2_TYPE = 0x0013
    NASA_POWER_CHANNEL3_TYPE = 0x0014
    NASA_POWER_CHANNEL4_TYPE = 0x0015
    NASA_POWER_CHANNEL5_TYPE = 0x0016
    NASA_POWER_CHANNEL6_TYPE = 0x0017
    NASA_POWER_CHANNEL7_TYPE = 0x0018
    NASA_POWER_CHANNEL8_TYPE = 0x0019
    NASA_POWER_CHANNEL1_USED = 0x001A
    NASA_POWER_CHANNEL2_USED = 0x001B
    NASA_POWER_CHANNEL3_USED = 0x001C
    NASA_POWER_CHANNEL4_USED = 0x001D
    NASA_POWER_CHANNEL5_USED = 0x001E
    NASA_POWER_CHANNEL6_USED = 0x001F
    NASA_POWER_CHANNEL7_USED = 0x0020
    NASA_POWER_CHANNEL8_USED = 0x0021
    NASA_STANDBY_MODE = 0x0023
    ENUM_AD_MULTI_TENANT_NO = 0x0025
    VAR_AD_ERROR_CODE1 = 0x0202
    NASA_ERROR_CODE2 = 0x0203
    NASA_ERROR_CODE3 = 0x0204
    NASA_ERROR_CODE4 = 0x0205
    NASA_ERROR_CODE5 = 0x0206
    VAR_AD_INSTALL_NUMBER_INDOOR = 0x0207
    NASA_OUTDOOR_ERVCOUNT = 0x0208
    NASA_OUTDOOR_EHSCOUNT = 0x0209
    NASA_NET_ADDRESS = 0x0210
    VAR_AD_INSTALL_NUMBER_MCU = 0x0211
    NASA_DEMAND_SYNC_TIME = 0x0213
    NASA_PEAK_TARGET_DEMAND = 0x0214
    NASA_PNP_NET_ADDRESS = 0x0217
    LVAR_AD_ADDRESS_MAIN = 0x0401
    LVAR_AD_ADDRESS_RMC = 0x0402
    NASA_RANDOM_ADDRESS = 0x0403
    NASA_ALL_POWER_CONSUMPTION_SET = 0x0406
    NASA_ALL_POWER_CONSUMPTION_CUMULATIVE = 0x0407
    LVAR_AD_ADDRESS_SETUP = 0x0408
    LVAR_AD_INSTALL_LEVEL_ALL = 0x0409
    LVAR_AD_INSTALL_LEVEL_OPERATION_POWER = 0x040A
    LVAR_AD_INSTALL_LEVEL_OPERATION_MODE = 0x040B
    LVAR_AD_INSTALL_LEVEL_FAN_MODE = 0x040C
    LVAR_AD_INSTALL_LEVEL_FAN_DIRECTION = 0x040D
    LVAR_AD_INSTALL_LEVEL_TEMP_TARGET = 0x040E
    LVAR_AD_INSTALL_LEVEL_KEEP_INDIVIDUAL_CONTROL = 0x040F
    LVAR_AD_INSTALL_LEVEL_OPERATION_MODE_ONLY = 0x0410
    LVAR_AD_INSTALL_LEVEL_COOL_MODE_UPPER = 0x0411
    LVAR_AD_INSTALL_LEVEL_COOL_MODE_LOWER = 0x0412
    LVAR_AD_INSTALL_LEVEL_HEAT_MODE_UPPER = 0x0413
    LVAR_AD_INSTALL_LEVEL_HEAT_MODE_LOWER = 0x0414
    LVAR_AD_INSTALL_LEVEL_CONTACT_CONTROL = 0x0415
    LVAR_AD_INSTALL_LEVEL_KEY_OPERATION_INPUT = 0x0416
    LVAR_AD___ = 0x0417
    LVAR_AD___1 = 0x0418
    LVAR_AD___2 = 0x0419
    LVAR_AD___3 = 0x041B
    NASA_POWER_CHANNEL1_ELECTRIC_VALUE = 0x041C
    NASA_POWER_CHANNEL2_ELECTRIC_VALUE = 0x041D
    NASA_POWER_CHANNEL3_ELECTRIC_VALUE = 0x041E
    NASA_POWER_CHANNEL4_ELECTRIC_VALUE = 0x041F
    NASA_POWER_CHANNEL5_ELECTRIC_VALUE = 0x0420
    NASA_POWER_CHANNEL6_ELECTRIC_VALUE = 0x0421
    NASA_POWER_CHANNEL7_ELECTRIC_VALUE = 0x0422
    NASA_POWER_CHANNEL8_ELECTRIC_VALUE = 0x0423
    NASA_PEAK_RATIO_CURRENT = 0x0434
    NASA_PEAK_RATIO_POTENTIAL = 0x0435
    NASA_PEAK_TOTAL_POWER = 0x0436
    NASA_PEAK_CURRENT_TARGET_DEMAND = 0x0437
    NASA_PEAK_FORCAST_DEMAND = 0x0438
    NASA_PEAK_TOP_DEMAND = 0x0439
    NASA_PEAK_TARGET_POWER = 0x043A
    NASA_POWER_CHANNEL1_PULSEVALUE = 0x043B
    NASA_POWER_CHANNEL2_PULSEVALUE = 0x043C
    NASA_POWER_CHANNEL3_PULSEVALUE = 0x043D
    NASA_POWER_CHANNEL4_PULSEVALUE = 0x043E
    NASA_POWER_CHANNEL5_PULSEVALUE = 0x043F
    NASA_POWER_CHANNEL6_PULSEVALUE = 0x0440
    NASA_POWER_CHANNEL7_PULSEVALUE = 0x0441
    NASA_POWER_CHANNEL8_PULSEVALUE = 0x0442
    NASA_PEAK_SYNC_TIME = 0x0443
    NASA_PEAK_CURRENT_DEMAND = 0x0444
    NASA_PEAK_REAL_VALUE = 0x0445
    LVAR_AD_MCU_PORT_SETUP = 0x0448
    STR_AD_OPTION_BASIC = 0x0600
    STR_AD_OPTION_INSTALL = 0x0601
    STR_AD_OPTION_INSTALL_2 = 0x0602
    STR_AD_OPTION_CYCLE = 0x0603
    NASA_PBAOPTION = 0x0604
    STR_AD_INFO_EQUIP_POSITION = 0x0605
    STR_AD_ID_SERIAL_NUMBER = 0x0607
    STR_AD_DBCODE_MICOM_MAIN = 0x0608
    STR_AD_DBCODE_EEPROM = 0x060C
    NASA_SIMPIM_SYNC_DATETIME = 0x0613
    NASA_SIMPIM_PASSWORD = 0x0619
    STR_AD_PRODUCT_MODEL_NAME = 0x061A
    STR_AD_PRODUCT_MAC_ADDRESS = 0x061C
    STR_AD_ID_MODEL_NAME = 0x061F
    NASA_IM_MASTER = 0x2000
    NASA_CHANGE_POLAR = 0x2001
    NASA_ADDRESSING_ASSIGN_CONFIRM_ADDRESS = 0x2002
    NASA_ADDRESSING = 0x2003
    NASA_PNP = 0x2004
    NASA_CHANGE_CONTROL_NETWORK_STATUS = 0x2006
    NASA_CHANGE_SET_NETWORK_STATUS = 0x2007
    NASA_CHANGE_LOCAL_NETWORK_STATUS = 0x2008
    NASA_CHANGE_MODULE_NETWORK_STATUS = 0x2009
    NASA_CHANGE_ALL_NETWORK_STATUS = 0x200A
    ENUM_NM_NETWORK_POSITINON_LAYER = 0x200F
    ENUM_NM_NETWORK_TRACKING_STATE = 0x2010
    ENUM_NM__ = 0x2012
    ENUM_NM__1 = 0x2015
    NASA_COMMU_MICOM_LED = 0x2017
    NASA_COMMU_MICOM_BUTTON = 0x2018
    ENUM_NM__2 = 0x20FF
    VAR_NM___ = 0x22F7
    VAR_NM___1 = 0x22F8
    VAR_NM___2 = 0x22F9
    VAR_NM___3 = 0x22FA
    VAR_NM___4 = 0x22FB
    VAR_NM___5 = 0x22FC
    VAR_NM___6 = 0x22FD
    VAR_NM___7 = 0x22FE
    VAR_NM___8 = 0x22FF
    NASA_ALL_LAYER_DEVICE_COUNT = 0x2400
    LVAR_NM___ = 0x2401
    LVAR_NM___1 = 0x24FB
    LVAR_NM___2 = 0x24FC
    ENUM_IN_OPERATION_POWER = 0x4000
    ENUM_IN_OPERATION_MODE = 0x4001
    ENUM_IN_OPERATION_MODE_REAL = 0x4002
    ENUM_IN_OPERATION_VENT_POWER = 0x4003
    ENUM_IN_OPERATION_VENT_MODE = 0x4004
    NASA_FANSPEED = 0x4006
    ENUM_IN_FAN_MODE_REAL = 0x4007
    ENUM_IN_FAN_VENT_MODE = 0x4008
    ENUM_IN___ = 0x400F
    ENUM_IN___1 = 0x4010
    ENUM_IN_LOUVER_HL_SWING = 0x4011
    ENUM_IN_LOUVER_HL_PART_SWING = 0x4012
    ENUM_IN___2 = 0x4015
    NASA_USE_WIREDREMOTE = 0x4018
    ENUM_IN___3 = 0x4019
    ENUM_IN___4 = 0x401B
    NASA_USE_SPI = 0x4023
    NASA_USE_FILTER_WARNING_TIME = 0x4024
    NASA_FILTER_CLEAN = 0x4025
    NASA_FILTER_WARNING = 0x4027
    ENUM_IN_STATE_THERMO = 0x4028
    ENUM_IN___5 = 0x4029
    ENUM_IN___6 = 0x402A
    ENUM_IN___7 = 0x402B
    ENUM_IN___8 = 0x402D
    ENUM_IN_STATE_DEFROST_MODE = 0x402E
    ENUM_IN_MTFC = 0x402F
    ENUM_IN___9 = 0x4031
    ENUM_IN___10 = 0x4035
    ENUM_IN_STATE_HUMIDITY_PERCENT = 0x4038
    NASA_CONTROL_OAINTAKE = 0x403D
    NASA_USE_MDS = 0x403E
    NASA_CONTROL_MDS = 0x403F
    NASA_USE_HUMIDIFICATION = 0x4040
    NASA_CONTROL_HUMIDIFICATION = 0x4041
    NASA_CONTROL_AUTO_CLEAN = 0x4042
    NASA_CONTROL_SPI = 0x4043
    NASA_USE_SILENCE = 0x4045
    ENUM_IN_SILENCE = 0x4046
    ENUM_IN___11 = 0x4047
    ENUM_IN___12 = 0x4048
    ENUM_IN___13 = 0x404F
    NASA_CONTROL_SILENCT = 0x4050
    ENUM_IN___14 = 0x4051
    ENUM_IN___15 = 0x4059
    NASA_USE_OUTER_COOL = 0x405B
    NASA_CONTROL_OUTER_COOL = 0x405C
    NASA_USE_DESIRED_HUMIDITY = 0x405D
    NASA_CONTROL_DESIRED_HUMIDITY = 0x405E
    ENUM_IN___16 = 0x405F
    ENUM_IN_ALTERNATIVE_MODE = 0x4060
    NASA_EHS_INDOOR_POWER = 0x4063
    NASA_EHS_INDOOR_OPMODE = 0x4064
    ENUM_IN_WATER_HEATER_POWER = 0x4065
    ENUM_IN_WATER_HEATER_MODE = 0x4066
    ENUM_IN_3WAY_VALVE = 0x4067
    ENUM_IN_SOLAR_PUMP = 0x4068
    ENUM_IN_THERMOSTAT1 = 0x4069
    ENUM_IN_THERMOSTAT2 = 0x406A
    NASA_SMART_GRID = 0x406B
    ENUM_IN_BACKUP_HEATER = 0x406C
    ENUM_IN_OUTING_MODE = 0x406D
    ENUM_IN_QUIET_MODE = 0x406E
    ENUM_IN_REFERENCE_EHS_TEMP = 0x406F
    ENUM_IN_DISCHAGE_TEMP_CONTROL = 0x4070
    ENUM_IN___17 = 0x4073
    ENUM_IN___18 = 0x4074
    ENUM_IN_ROOM_TEMP_SENSOR = 0x4076
    ENUM_IN___19 = 0x4077
    ENUM_IN___20 = 0x407B
    ENUM_IN___21 = 0x407D
    ENUM_IN_LOUVER_LR_SWING = 0x407E
    ENUM_IN___22 = 0x4085
    ENUM_IN___23 = 0x4086
    ENUM_IN_BOOSTER_HEATER = 0x4087
    ENUM_IN_STATE_WATER_PUMP = 0x4089
    ENUM_IN_2WAY_VALVE = 0x408A
    ENUM_IN_FSV_2041 = 0x4093
    ENUM_IN_FSV_2081 = 0x4094
    ENUM_IN_FSV_2091 = 0x4095
    ENUM_IN_FSV_2092 = 0x4096
    ENUM_IN_FSV_3011 = 0x4097
    ENUM_IN_FSV_3031 = 0x4098
    ENUM_IN_FSV_3041 = 0x4099
    ENUM_IN_FSV_3042 = 0x409A
    ENUM_IN_FSV_3051 = 0x409B
    ENUM_IN_FSV_3061 = 0x409C
    ENUM_IN_FSV_3071 = 0x409D
    ENUM_IN_FSV_4011 = 0x409E
    ENUM_IN_FSV_4021 = 0x409F
    ENUM_IN_FSV_4022 = 0x40A0
    ENUM_IN_FSV_4023 = 0x40A1
    ENUM_IN_FSV_4031 = 0x40A2
    ENUM_IN_FSV_4032 = 0x40A3
    ENUM_IN_FSV_5041 = 0x40A4
    ENUM_IN_FSV_5042 = 0x40A5
    ENUM_IN_FSV_5043 = 0x40A6
    ENUM_IN_FSV_5051 = 0x40A7
    NASA_DHW_OPMODE_SUPPORT = 0x40B1
    ENUM_IN_FSV_5061 = 0x40B4
    ENUM_IN___24 = 0x40B5
    ENUM_IN_STATE_AUTO_STATIC_PRESSURE_RUNNING = 0x40BB
    NASA_VACANCY_STATUS = 0x40BC
    ENUM_IN_EMPTY_ROOM_CONTROL_USED = 0x40BD
    ENUM_IN_FSV_4041 = 0x40C0
    ENUM_IN_FSV_4044 = 0x40C1
    ENUM_IN_FSV_4051 = 0x40C2
    ENUM_IN_FSV_4053 = 0x40C3
    ENUM_IN_WATERPUMP_PWM_VALUE = 0x40C4
    ENUM_IN_THERMOSTAT_WATER_HEATER = 0x40C5
    ENUM_IN___25 = 0x40C6
    NASA_AHUPANEL_ENTHALPY_CONTROL = 0x40C7
    NASA_AHUPANEL_DUTY_CONTROL = 0x40C8
    NASA_AHUPANEL_SUMMERNIGHT_CONTROL = 0x40C9
    NASA_AHUPANEL_CO2_CONTROL = 0x40CA
    NASA_AHUPANEL_ENERGYMANAGE_CONTROL = 0x40CB
    NASA_AHUPANEL_RA_SMOKE_DECTION_STATUS = 0x40CC
    NASA_AHUPANEL_SA_FAN_STATUS = 0x40CD
    NASA_AHUPANEL_RA_FAN_ONOFF_STATUS = 0x40CE
    NASA_AHUPANEL_ERROR_STATUS = 0x40CF
    NASA_AHUPANEL_HEATER_ONOFF_STATUS = 0x40D0
    NASA_AHUPANEL_SA_FAN_ONOFF_STATUS = 0x40D1
    NASA_AHUPANEL_SMOKE_DECTION_CONTROL = 0x40D2
    ENUM_IN_ENTER_ROOM_CONTROL_USED = 0x40D5
    ENUM_IN_ERROR_HISTORY_CLEAR_FOR_HASS = 0x40D6
    ENUM_IN___26 = 0x40E3
    ENUM_IN_CHILLER_WATERLAW_SENSOR = 0x40E7
    ENUM_IN_CHILLER_WATERLAW_ON_OFF = 0x40F7
    ENUM_IN_CHILLLER_SETTING_SILENT_LEVEL = 0x40FB
    ENUM_IN_CHILLER_SETTING_DEMAND_LEVEL = 0x40FC
    ENUM_IN_CHILLER_EXT_WATER_OUT_INPUT = 0x4101
    ENUM_IN_STATE_FLOW_CHECK = 0x4102
    ENUM_IN_WATER_VALVE_1_ON_OFF = 0x4103
    ENUM_IN_WATER_VALVE_2_ON_OFF = 0x4104
    ENUM_IN_ENTHALPY_CONTROL_STATE = 0x4105
    ENUM_IN_FSV_5033 = 0x4107
    ENUM_IN_TDM_INDOOR_TYPE = 0x4108
    ENUM_IN_FREE_COOLING_STATE = 0x410D
    ENUM_IN_3WAY_VALVE_2 = 0x4113
    ENUM_IN___27 = 0x4117
    ENUM_IN_ROOM_TEMP_SENSOR_ZONE2 = 0x4118
    ENUM_IN_OPERATION_POWER_ZONE1 = 0x4119
    ENUM_IN_FSV_4061 = 0x411A
    ENUM_IN_FSV_5081 = 0x411B
    ENUM_IN_FSV_5091 = 0x411C
    ENUM_IN_FSV_5094 = 0x411D
    ENUM_IN_OPERATION_POWER_ZONE2 = 0x411E
    ENUM_IN_PV_CONTACT_STATE = 0x4123
    ENUM_IN_SG_READY_MODE_STATE = 0x4124
    ENUM_IN_FSV_LOAD_SAVE = 0x4125
    ENUM_IN_FSV_2093 = 0x4127
    ENUM_IN_FSV_5022 = 0x4128
    ENUM_IN_FSV_2094 = 0x412A
    ENUM_IN_FSV_LOAD_SAVE1 = 0x412D
    ENUM_IN_GAS_LEVEL = 0x4147
    ENUM_IN_DIFFUSER_OPERATION_POWER = 0x4149
    VAR_IN_TEMP_TARGET_F = 0x4201
    VAR_IN_TEMP_DISCHARGE_REQUEST = 0x4202
    VAR_IN_TEMP_ROOM_F = 0x4203
    VAR_IN___ = 0x4204
    VAR_IN_TEMP_EVA_IN_F = 0x4205
    VAR_IN_TEMP_EVA_OUT_F = 0x4206
    VAR_IN_TEMP_ELECTRIC_HEATER_F = 0x4207
    NASA_EVA_INHOLE_TEMP = 0x4208
    NASA_SET_DISCHARGE = 0x4209
    VAR_IN_TEMP_DISCHARGE = 0x420B
    NASA_INDOOR_OUTER_TEMP = 0x420C
    VAR_IN_CAPACITY_REQUEST = 0x4211
    VAR_IN_CAPACITY_ABSOLUTE = 0x4212
    VAR_IN___1 = 0x4213
    VAR_IN_EEV_VALUE_REAL_1 = 0x4217
    VAR_IN_EEV_VALUE_REAL_2 = 0x4218
    NASA_INDOOR_CURRENT_EEV3 = 0x4219
    NASA_INDOOR_CURRENT_EEV4 = 0x421A
    VAR_IN_SENSOR_CO2_PPM = 0x421B
    NASA_INDOOR_AIRCLEANFAN_CURRENT_RPM = 0x4220
    VAR_IN_MODEL_INFORMATION = 0x4229
    VAR_IN_TEMP_DISCHARGE_COOL_TARGET_F = 0x422A
    VAR_IN_TEMP_DISCHARGE_HEAT_TARGET_F = 0x422B
    VAR_IN_TEMP_WATER_HEATER_TARGET_F = 0x4235
    VAR_IN_TEMP_WATER_IN_F = 0x4236
    VAR_IN_TEMP_WATER_TANK_F = 0x4237
    VAR_IN_TEMP_WATER_OUT_F = 0x4238
    VAR_IN_TEMP_WATER_OUT2_F = 0x4239
    VAR_IN_TEMP_ROOM_ZONE1 = 0x423A
    VAR_IN___2 = 0x423E
    VAR_IN_TEMP_WATER_OUTLET_TARGET_F = 0x4247
    VAR_IN_TEMP_WATER_LAW_TARGET_F = 0x4248
    VAR_IN_FSV_1011 = 0x424A
    VAR_IN_FSV_1012 = 0x424B
    VAR_IN_FSV_1021 = 0x424C
    VAR_IN_FSV_1022 = 0x424D
    VAR_IN_FSV_1031 = 0x424E
    VAR_IN_FSV_1032 = 0x424F
    VAR_IN_FSV_1041 = 0x4250
    VAR_IN_FSV_1042 = 0x4251
    VAR_IN_FSV_1051 = 0x4252
    VAR_IN_FSV_1052 = 0x4253
    VAR_IN_FSV_2011 = 0x4254
    VAR_IN_FSV_2012 = 0x4255
    VAR_IN_FSV_2021 = 0x4256
    VAR_IN_FSV_2022 = 0x4257
    VAR_IN_FSV_2031 = 0x4258
    VAR_IN_FSV_2032 = 0x4259
    VAR_IN_FSV_2051 = 0x425A
    VAR_IN_FSV_2052 = 0x425B
    VAR_IN_FSV_2061 = 0x425C
    VAR_IN_FSV_2062 = 0x425D
    VAR_IN_FSV_2071 = 0x425E
    VAR_IN_FSV_2072 = 0x425F
    VAR_IN_FSV_3021 = 0x4260
    VAR_IN_FSV_3022 = 0x4261
    VAR_IN_FSV_3023 = 0x4262
    VAR_IN_FSV_3024 = 0x4263
    VAR_IN_FSV_3025 = 0x4264
    VAR_IN_FSV_3026 = 0x4265
    VAR_IN_FSV_3032 = 0x4266
    VAR_IN_FSV_3033 = 0x4267
    VAR_IN_FSV_3034 = 0x4268
    VAR_IN_FSV_3043 = 0x4269
    VAR_IN_FSV_3044 = 0x426A
    VAR_IN_FSV_3045 = 0x426B
    VAR_IN_FSV_3052 = 0x426C
    VAR_IN_FSV_4012 = 0x426D
    VAR_IN_FSV_4013 = 0x426E
    VAR_IN_FSV_4014 = 0x426F
    VAR_IN_FSV_4024 = 0x4270
    VAR_IN_FSV_4025 = 0x4271
    VAR_IN_FSV_4033 = 0x4272
    VAR_IN_FSV_5011_WATEROUT_TEMP_COOLING = 0x4273
    VAR_IN_FSV_5012_ROOM_TEMP_COOLING = 0x4274
    VAR_IN_FSV_5013_WATEROUT_TEMP_HEATING = 0x4275
    VAR_IN_FSV_5014_ROOM_TEMP_HEATING = 0x4276
    VAR_IN_FSV_5015_COOL_WL1_TEMP = 0x4277
    VAR_IN_FSV_5016_COOL_WL2_TEMP = 0x4278
    VAR_IN_FSV_5017_HEAT_WL1_TEMP = 0x4279
    VAR_IN_FSV_5018_HEAT_WL2_TEMP = 0x427A
    VAR_IN_FSV_5019_DHW_TANK_TEMP = 0x427B
    VAR_IN_FSV_5021_DHW_SAVING_TEMP = 0x427C
    VAR_IN_FSV_5031 = 0x427D
    VAR_IN_FSV_5032 = 0x427E
    VAR_IN_TEMP_WATER_LAW_F = 0x427F
    NASA_INDOOR_POWER_CONSUMPTION = 0x4284
    VAR_IN_FSV_4042_TARGET_DELTA_TEMP_HEATING = 0x4286
    VAR_IN_FSV_4043_TARGET_DELTA_TEMP_COOLING = 0x4287
    VAR_IN_FSV_4045_MIXING_VALVE_CONTROL_INTERVAL = 0x4288
    VAR_IN_FSV_4046_MIXING_VALVE_RUNNING_TIME = 0x4289
    VAR_IN_FSV_4052_PUMP_TARGET_DELTA_TEMP = 0x428A
    VAR_IN_TEMP_MIXING_VALVE_F = 0x428C
    VAR_IN___3 = 0x428D
    NASA_AHUPANEL_TARGET_HUMIDITY = 0x4290
    NASA_AHUPANEL_OA_DAMPER_TARGET_RATE = 0x4291
    NASA_AHUPANEL_RA_TEMP = 0x4292
    NASA_AHUPANEL_RA_HUMIDITY = 0x4293
    NASA_AHUPANEL_EA_RATE = 0x4294
    NASA_AHUPANEL_OA_TEMP = 0x4295
    NASA_AHUPANEL_OA_HUMIDITY = 0x4296
    VAR_AHU_PANEL_SA_TEMP = 0x4297
    VAR_AHU_PANEL_SA_HUMIDITY = 0x4298
    NASA_AHUPANEL_STATIC_PRESSURE = 0x4299
    NASA_AHUPANEL_MIXING_TEMP = 0x429A
    NASA_AHUPANEL_MIXING_RATE = 0x429B
    NASA_AHUPANEL_POINT_STATUS = 0x429C
    VAR_IN_FAN_CURRENT_RPM_SUCTION1 = 0x429F
    VAR_IN_FAN_CURRENT_RPM_SUCTION2 = 0x42A1
    VAR_IN_FAN_CURRENT_RPM_SUCTION3 = 0x42A3
    VAR_IN_TEMP_PANEL_AIR_COOL1_F = 0x42A5
    VAR_IN_TEMP_PANEL_AIR_COOL2_F = 0x42A6
    VAR_IN_TEMP_PANEL_ROOM_COOL1_F = 0x42A7
    VAR_IN_TEMP_PANEL_ROOM_COOL2_F = 0x42A8
    VAR_IN_TEMP_PANEL_TARGET_COOL1_F = 0x42A9
    VAR_IN_TEMP_PANEL_TARGET_COOL2_F = 0x42AA
    VAR_IN_TEMP_PANEL_AIR_HEAT1_F = 0x42AB
    VAR_IN_TEMP_PANEL_AIR_HEAT2_F = 0x42AC
    VAR_IN_TEMP_PANEL_ROOM_HEAT1_F = 0x42AD
    VAR_IN_TEMP_PANEL_ROOM_HEAT2_F = 0x42AE
    VAR_IN_TEMP_PANEL_TARGET_HEAT1_F = 0x42AF
    VAR_IN_TEMP_PANEL_TARGET_HEAT2_F = 0x42B0
    VAR_IN_MCC_GROUP_MODULE_ADDRESS = 0x42B1
    VAR_IN_MCC_GROUP_MAIN = 0x42B2
    VAR_IN_MCC_MODULE_MAIN = 0x42B3
    VAR_IN_TEMP_EVA2_IN_F = 0x42C2
    VAR_IN_TEMP_EVA2_OUT_F = 0x42C3
    VAR_IN_CHILLER_PHE_IN_P = 0x42C4
    VAR_IN_CHILLER_PHE_OUT_P = 0x42C5
    VAR_IN_CHILLER_EXTERNAL_TEMPERATURE = 0x42C9
    VAR_IN_MODULATING_VALVE_1 = 0x42CA
    VAR_IN_MODULATING_VALVE_2 = 0x42CB
    VAR_IN_MODULATING_FAN = 0x42CC
    VAR_IN_TEMP_WATER_IN2_F = 0x42CD
    VAR_IN_FSV_3046 = 0x42CE
    VAR_IN_ENTHALPY_SENSOR_OUTPUT = 0x42CF
    VAR_IN_EXT_VARIABLE_DAMPER_OUTPUT = 0x42D0
    VAR_IN_DUST_SENSOR_PM10_0_VALUE = 0x42D1
    VAR_IN_DUST_SENSOR_PM2_5_VALUE = 0x42D2
    VAR_IN_DUST_SENSOR_PM1_0_VALUE = 0x42D3
    VAR_IN_TEMP_ZONE2_F = 0x42D4
    VAR_IN_TEMP_TARGET_ZONE2_F = 0x42D6
    VAR_IN_TEMP_WATER_OUTLET_TARGET_ZONE2_F = 0x42D7
    VAR_IN_TEMP_WATER_OUTLET_ZONE1_F = 0x42D8
    VAR_IN_TEMP_WATER_OUTLET_ZONE2_F = 0x42D9
    VAR_IN_TEMP_ROOM_ZONE2 = 0x42DA
    VAR_IN_FSV_5082 = 0x42DB
    VAR_IN_FSV_5083 = 0x42DC
    VAR_IN_FSV_5092 = 0x42DD
    VAR_IN_FSV_5093 = 0x42DE
    VAR_IN_FLOW_SENSOR_VOLTAGE = 0x42E8
    VAR_IN_FLOW_SENSOR_CALC = 0x42E9
    VAR_IN_FSV_3081 = 0x42ED
    VAR_IN_FSV_3082 = 0x42EE
    VAR_IN_FSV_3083 = 0x42EF
    VAR_IN_FSV_5023 = 0x42F0
    VAR_OUT_COMP_FREQ_RATE_CONTROL = 0x42F1
    VAR_IN___4 = 0x4301
    VAR_IN_CAPACITY_VENTILATION_REQUEST = 0x4302
    LVAR_IN___ = 0x4401
    NASA_GROUPCONTROL_BIT1 = 0x4405
    NASA_GROUPCONTROL_BIT2 = 0x4406
    NASA_GROUPCONTROL_BIT3 = 0x4407
    LVAR_IN_DEVICE_STAUS_HEATPUMP_BOILER = 0x440A
    LVAR_IN___1 = 0x440E
    NASA_ERROR_INOUT = 0x440F
    LVAR_IN_AUTO_STATIC_PRESSURE = 0x4415
    LVAR_IN_EMPTY_ROOM_CONTROL_DATA = 0x4418
    LVAR_IN_ENTER_ROOM_CONTROL_DATA = 0x441B
    LVAR_IN_ETO_COOL_CONTROL_DATA = 0x441F
    LVAR_IN_ETO_HEAT_CONTROL_DATA = 0x4420
    NASA_MINUTE_SINCE_INSTALL = 0x4423
    NASA_MINUTES_ACTIVE = 0x4424
    NASA_GEN_POWER_LAST_MINUTE = 0x4426
    NASA_TOTAL_GEN_POWER = 0x4427
    STR_IN_INSTALL_INDOOR_SETUP_INFO = 0x4604
    NASA_INDOOR_SETTING_MIN_MAX_TEMP = 0x4608
    STR_IN___ = 0x4612
    NASA_EHS_SETTING_MIN_MAX_TEMP = 0x4619
    NASA_EHS_FSV_SETTING_MIN_MAX_TEMP = 0x461A
    NASA_AHUPANEL_AHUKIT_ADDRESS = 0x461C
    NASA_AHUPANEL_PANEL_OPTION = 0x461D
    STR_IN_ERROR_HISTORY_FOR_HASS = 0x461E
    ENUM_OUT_OPERATION_SERVICE_OP = 0x8000
    ENUM_OUT_OPERATION_ODU_MODE = 0x8001
    ENUM_OUT___ = 0x8002
    ENUM_OUT_OPERATION_HEATCOOL = 0x8003
    ENUM_OUT___1 = 0x8005
    ENUM_OUT___2 = 0x800D
    ENUM_OUT_LOAD_COMP1 = 0x8010
    ENUM_OUT_LOAD_COMP2 = 0x8011
    ENUM_OUT_LOAD_COMP3 = 0x8012
    ENUM_OUT_LOAD_CCH1 = 0x8013
    ENUM_OUT_LOAD_CCH2 = 0x8014
    NASA_OUTDOOR_CCH3_STATUS = 0x8015
    NASA_OUTDOOR_ACCUMULATOR_CCH = 0x8016
    ENUM_OUT_LOAD_HOTGAS = 0x8017
    ENUM_OUT_LOAD_HOTGAS2 = 0x8018
    ENUM_OUT_LOAD_LIQUID = 0x8019
    ENUM_OUT_LOAD_4WAY = 0x801A
    ENUM_OUT_LOAD_MAINCOOL = 0x801F
    ENUM_OUT_LOAD_OUTEEV = 0x8020
    ENUM_OUT_LOAD_EVI_BYPASS = 0x8021
    ENUM_OUT_LOAD_EVI_SOL1 = 0x8022
    ENUM_OUT_LOAD_EVI_SOL2 = 0x8023
    NASA_OUTDOOR_EVI_SOL3_VALVE = 0x8024
    ENUM_OUT_LOAD_GASCHARGE = 0x8025
    ENUM_OUT_LOAD_WATER = 0x8026
    ENUM_OUT_LOAD_PUMPOUT = 0x8027
    ENUM_OUT_LOAD_4WAY2 = 0x802A
    ENUM_OUT___3 = 0x8031
    ENUM_OUT___4 = 0x8032
    ENUM_OUT___5 = 0x8033
    ENUM_OUT_LOAD_LIQUIDTUBE = 0x8034
    ENUM_OUT_LOAD_ACCRETURN = 0x8037
    ENUM_OUT_LOAD_FLOW_SWITCH = 0x803B
    ENUM_OUT_OPERATION_AUTO_INSPECT_STEP = 0x803C
    ENUM_OUT___6 = 0x803F
    ENUM_OUT___7 = 0x8043
    ENUM_OUT___8 = 0x8045
    ENUM_OUT_OP_TEST_OP_COMPLETE = 0x8046
    NASA_OUTDOOR_SERVICEOPERATION = 0x8047
    ENUM_OUT___9 = 0x8048
    ENUM_OUT_MCU_LOAD_COOL_A = 0x8049
    ENUM_OUT_MCU_LOAD_HEAT_A = 0x804A
    ENUM_OUT_MCU_LOAD_COOL_B = 0x804B
    ENUM_OUT_MCU_LOAD_HEAT_B = 0x804C
    ENUM_OUT_MCU_LOAD_COOL_C = 0x804D
    ENUM_OUT_MCU_LOAD_HEAT_C = 0x804E
    ENUM_OUT_MCU_LOAD_COOL_D = 0x804F
    ENUM_OUT_MCU_LOAD_HEAT_D = 0x8050
    ENUM_OUT_MCU_LOAD_COOL_E = 0x8051
    ENUM_OUT_MCU_LOAD_HEAT_E = 0x8052
    ENUM_OUT_MCU_LOAD_COOL_F = 0x8053
    ENUM_OUT_MCU_LOAD_HEAT_F = 0x8054
    ENUM_OUT_MCU_LOAD_LIQUID = 0x8055
    ENUM_OUT_MCU_PORT0_INDOOR_ADDR = 0x8058
    ENUM_OUT_MCU_PORT1_INDOOR_ADDR = 0x8059
    ENUM_OUT_MCU_PORT2_INDOOR_ADDR = 0x805A
    ENUM_OUT_MCU_PORT3_INDOOR_ADDR = 0x805B
    ENUM_OUT_MCU_PORT4_INDOOR_ADDR = 0x805C
    ENUM_OUT_MCU_PORT5_INDOOR_ADDR = 0x805D
    ENUM_OUT___10 = 0x805E
    ENUM_OUT_DEICE_STEP_INDOOR = 0x8061
    NASA_OUTDOOR_LOGICAL_DEFROST_STEP = 0x8062
    ENUM_OUT___11 = 0x8063
    NASA_OUTDOOR_SYSTEM_RESET = 0x8065
    NASA_OUTDOOR_OPMODELIMIT = 0x8066
    ENUM_OUT___12 = 0x8077
    ENUM_OUT___13 = 0x8078
    ENUM_OUT___14 = 0x8079
    ENUM_OUT___15 = 0x807A
    ENUM_OUT___16 = 0x807B
    ENUM_OUT___17 = 0x807C
    ENUM_OUT___18 = 0x807D
    ENUM_OUT___19 = 0x807E
    ENUM_OUT___20 = 0x807F
    NASA_OUTDOOR_EXT_CMD_OPERATION = 0x8081
    ENUM_OUT___21 = 0x8083
    ENUM_OUT___22 = 0x808C
    ENUM_OUT___23 = 0x808D
    ENUM_OUT_OP_CHECK_REF_STEP = 0x808E
    ENUM_OUT___24 = 0x808F
    ENUM_OUT_INSTALL_ODU_COUNT = 0x8092
    ENUM_OUT_CONTROL_FAN_NUM = 0x8099
    ENUM_OUT_CHECK_REF_RESULT = 0x809C
    NASA_OUTDOOR_COOLONLY_MODEL = 0x809D
    ENUM_OUT_LOAD_CBOX_COOLING_FAN = 0x809E
    ENUM_OUT_STATE_BACKUP_OPER = 0x80A5
    ENUM_OUT_STATE_COMP_PROTECT_OPER = 0x80A6
    NASA_OUTDOOR_DRED_LEVEL = 0x80A7
    ENUM_OUT___25 = 0x80A8
    ENUM_OUT___26 = 0x80A9
    ENUM_OUT___27 = 0x80AA
    ENUM_OUT___28 = 0x80AB
    NASA_OUTDOOR_ACCUM_RETURN2_VALVE = 0x80AC
    ENUM_OUT___29 = 0x80AE
    ENUM_OUT_LOAD_BASEHEATER = 0x80AF
    ENUM_OUT___30 = 0x80B1
    NASA_OUTDOOR_CH_SWITCH_VALUE = 0x80B2
    ENUM_OUT_STATE_ACCUM_VALVE_ONOFF = 0x80B4
    ENUM_OUT___31 = 0x80B6
    ENUM_OUT_LOAD_OIL_BYPASS1 = 0x80B8
    ENUM_OUT_LOAD_OIL_BYPASS2 = 0x80B9
    ENUM_OUT___32 = 0x80BC
    ENUM_OUT_OP_A2_CURRENTMODE = 0x80BE
    ENUM_OUT_LOAD_A2A_VALVE = 0x80C1
    ENUM_OUT___33 = 0x80CE
    ENUM_OUT_LOAD_PHEHEATER = 0x80D7
    ENUM_OUT_EHS_WATEROUT_TYPE = 0x80D8
    NASA_OUTDOOR_OPMODE_OPTION = 0x8200
    VAR_OUT___ = 0x8201
    VAR_OUT_INSTALL_COMP_NUM = 0x8202
    VAR_OUT_SENSOR_AIROUT = 0x8204
    VAR_OUT_SENSOR_HIGHPRESS = 0x8206
    VAR_OUT_SENSOR_LOWPRESS = 0x8208
    VAR_OUT_SENSOR_DISCHARGE1 = 0x820A
    VAR_OUT_SENSOR_DISCHARGE2 = 0x820C
    VAR_OUT_SENSOR_DISCHARGE3 = 0x820E
    NASA_OUTDOOR_SUMPTEMP = 0x8210
    VAR_OUT_SENSOR_COMPRESSOR_CT1 = 0x8217
    VAR_OUT_SENSOR_CONDOUT = 0x8218
    VAR_OUT_SENSOR_SUCTION = 0x821A
    VAR_OUT_SENSOR_DOUBLETUBE = 0x821C
    VAR_OUT_SENSOR_EVIIN = 0x821E
    VAR_OUT_SENSOR_EVIOUT = 0x8220
    NASA_OUTDOOR_OLP_TEMP = 0x8222
    VAR_OUT_CONTROL_TARGET_DISCHARGE = 0x8223
    VAR_OUT___1 = 0x8224
    VAR_OUT___2 = 0x8225
    VAR_OUT_LOAD_FANSTEP1 = 0x8226
    NASA_OUTDOOR_FAN_STEP2 = 0x8227
    NASA_OUTDOOR_LOADINGTIME = 0x8228
    VAR_OUT_LOAD_OUTEEV1 = 0x8229
    VAR_OUT_LOAD_OUTEEV2 = 0x822A
    VAR_OUT_LOAD_OUTEEV3 = 0x822B
    VAR_OUT_LOAD_OUTEEV4 = 0x822C
    VAR_OUT_LOAD_OUTEEV5 = 0x822D
    VAR_OUT_LOAD_EVIEEV = 0x822E
    NASA_OUTDOOR_HREEV = 0x822F
    NASA_OUTDOOR_RUNNING_SUM_CAPA = 0x8230
    NASA_OUTDOOR_HEATING_PERCENT = 0x8231
    NASA_OUTDOOR_OPERATION_CAPA_SUM = 0x8233
    VAR_OUT___3 = 0x8234
    VAR_OUT_ERROR_CODE = 0x8235
    VAR_OUT_CONTROL_ORDER_CFREQ_COMP1 = 0x8236
    VAR_OUT_CONTROL_TARGET_CFREQ_COMP1 = 0x8237
    VAR_OUT_CONTROL_CFREQ_COMP1 = 0x8238
    VAR_OUT___4 = 0x8239
    VAR_OUT_SENSOR_DCLINK_VOLTAGE = 0x823B
    VAR_OUT___5 = 0x823C
    VAR_OUT_LOAD_FANRPM1 = 0x823D
    VAR_OUT_LOAD_FANRPM2 = 0x823E
    NASA_OUTDOOR_CONTROL_PRIME_UNIT = 0x823F
    NASA_OUTDOOR_ODU_CAPA1 = 0x8240
    NASA_OUTDOOR_ODU_CAPA2 = 0x8241
    VAR_OUT___6 = 0x8243
    NASA_OUTDOOR_OIL_RECOVERY_STEP = 0x8244
    NASA_OUTDOOR_OIL_BALANCE_STEP = 0x8245
    NASA_OUTDOOR_DEFROST_STEP = 0x8247
    NASA_OUTDOOR_SAFETY_START = 0x8248
    VAR_OUT___7 = 0x8249
    VAR_OUT___8 = 0x824B
    VAR_OUT___9 = 0x824C
    VAR_OUT_CONTROL_REFRIGERANTS_VOLUME = 0x824F
    VAR_OUT_SENSOR_IPM1 = 0x8254
    VAR_OUT_SENSOR_IPM2 = 0x8255
    VAR_OUT___10 = 0x825A
    VAR_OUT___11 = 0x825B
    VAR_OUT___12 = 0x825C
    VAR_OUT___13 = 0x825D
    VAR_OUT_SENSOR_TEMP_WATER = 0x825E
    VAR_OUT_SENSOR_PIPEIN1 = 0x825F
    VAR_OUT_SENSOR_PIPEIN2 = 0x8260
    VAR_OUT_SENSOR_PIPEIN3 = 0x8261
    VAR_OUT_SENSOR_PIPEIN4 = 0x8262
    VAR_OUT_SENSOR_PIPEIN5 = 0x8263
    VAR_OUT_SENSOR_PIPEOUT1 = 0x8264
    VAR_OUT_SENSOR_PIPEOUT2 = 0x8265
    VAR_OUT_SENSOR_PIPEOUT3 = 0x8266
    VAR_OUT_SENSOR_PIPEOUT4 = 0x8267
    VAR_OUT_SENSOR_PIPEOUT5 = 0x8268
    VAR_OUT_MCU_SENSOR_SUBCOOLER_IN = 0x826B
    VAR_OUT_MCU_SENSOR_SUBCOOLER_OUT = 0x826C
    VAR_OUT_MCU_SUBCOOLER_EEV = 0x826D
    VAR_OUT_MCU_CHANGE_OVER_EEV1 = 0x826E
    VAR_OUT_MCU_CHANGE_OVER_EEV2 = 0x826F
    VAR_OUT_MCU_CHANGE_OVER_EEV3 = 0x8270
    VAR_OUT_MCU_CHANGE_OVER_EEV4 = 0x8271
    VAR_OUT_MCU_CHANGE_OVER_EEV5 = 0x8272
    VAR_OUT_MCU_CHANGE_OVER_EEV6 = 0x8273
    VAR_OUT_CONTROL_ORDER_CFREQ_COMP2 = 0x8274
    VAR_OUT_CONTROL_TARGET_CFREQ_COMP2 = 0x8275
    VAR_OUT_CONTROL_CFREQ_COMP2 = 0x8276
    VAR_OUT_SENSOR_CT2 = 0x8277
    VAR_OUT_SENSOR_OCT1 = 0x8278
    NASA_OUTDOOR_OCT2 = 0x8279
    VAR_OUT_CONTROL_DSH1 = 0x827A
    NASA_OUTDOOR_ODU_CAPA3 = 0x827E
    NASA_OUTDOOR_ODU_CAPA4 = 0x827F
    VAR_OUT_SENSOR_TOP1 = 0x8280
    VAR_OUT_SENSOR_TOP2 = 0x8281
    NASA_OUTDOOR_TOP_SENSOR_TEMP3 = 0x8282
    VAR_OUT_INSTALL_CAPA = 0x8287
    NASA_OUTDOOR_COOL_SUM_CAPA = 0x8298
    VAR_OUT_SENSOR_SUCTION2_1SEC = 0x829A
    NASA_OUTDOOR_CT_RESTRICT_OPTION = 0x829B
    NASA_OUTDOOR_COMPENSATE_COOL_CAPA = 0x829C
    NASA_OUTDOOR_COMPENSATE_HEAT_CAPA = 0x829D
    VAR_OUT_SENSOR_SAT_TEMP_HIGH_PRESSURE = 0x829F
    VAR_OUT_SENSOR_SAT_TEMP_LOW_PRESSURE = 0x82A0
    VAR_OUT___14 = 0x82A2
    NASA_OUTDOOR_CT3 = 0x82A3
    NASA_OUTDOOR_OCT3 = 0x82A4
    NASA_OUTDOOR_FAN_IPM1_TEMP = 0x82A6
    NASA_OUTDOOR_FAN_IPM2_TEMP = 0x82A7
    VAR_OUT_CONTROL_IDU_TOTAL_ABSCAPA = 0x82A8
    VAR_OUT_CONTROL_IDU_TOTAL_ABSCAPA2 = 0x82A9
    VAR_OUT_INSTALL_COND_SIZE = 0x82AF
    VAR_OUT___15 = 0x82B2
    NASA_OUTDOOR_DCLINK2_VOLT = 0x82B3
    VAR_OUT___16 = 0x82B5
    VAR_OUT___17 = 0x82B6
    VAR_OUT_SENSOR_MIDPRESS = 0x82B8
    NASA_OUTDOOR_FAN_CT1 = 0x82B9
    NASA_OUTDOOR_FAN_CT2 = 0x82BA
    VAR_OUT_PROJECT_CODE = 0x82BC
    VAR_OUT_LOAD_FLUX_VARIABLE_VALVE = 0x82BD
    VAR_OUT_SENSOR_CONTROL_BOX = 0x82BE
    VAR_OUT_SENSOR_CONDOUT2 = 0x82BF
    NASA_OUTDOOR_COMP3_ORDER_HZ = 0x82C0
    NASA_OUTDOOR_COMP3_TARGET_HZ = 0x82C1
    NASA_OUTDOOR_COMP3_RUN_HZ = 0x82C2
    NASA_OUTDOOR_DCLINK3_VOLT = 0x82C3
    NASA_OUTDOOR_IPM_TEMP3 = 0x82C4
    VAR_OUT_SENSOR_ACCUM_TEMP = 0x82C8
    VAR_OUT_SENSOR_ENGINE_WATER_TEMP = 0x82C9
    VAR_OUT_OIL_BYPASS_VALVE = 0x82CA
    VAR_OUT_SUCTION_OVER_HEAT = 0x82CB
    VAR_OUT_SUB_COND_OVER_HEAT = 0x82CC
    VAR_OUT_OVER_COOL = 0x82CD
    VAR_OUT_COND_OVER_COOL = 0x82CE
    VAR_OUT_ENGINE_RPM = 0x82CF
    VAR_OUT_APPEARANCE_RPM = 0x82D0
    VAR_OUT___18 = 0x82D1
    VAR_OUT_SUB_COND_EEV_STEP = 0x82D2
    NASA_OUTDOOR_SNOW_LEVEL = 0x82D3
    VAR_OUT___19 = 0x82D4
    NASA_OUTDOOR_UPL_TP_COOL = 0x82D5
    NASA_OUTDOOR_UPL_TP_HEAT = 0x82D6
    VAR_OUT___20 = 0x82D9
    VAR_OUT___21 = 0x82DA
    VAR_OUT_PHASE_CURRENT = 0x82DB
    VAR_OUT___22 = 0x82DC
    VAR_OUT___23 = 0x82DD
    NASA_OUTDOOR_EVA_IN = 0x82DE
    VAR_OUT_SENSOR_TW1 = 0x82DF
    VAR_OUT_SENSOR_TW2 = 0x82E0
    VAR_OUT___24 = 0x82E1
    VAR_OUT_PRODUCT_OPTION_CAPA = 0x82E3
    VAR_OUT_SENSOR_TOTAL_SUCTION = 0x82E7
    VAR_OUT_LOAD_MCU_HR_BYPASS_EEV = 0x82E8
    VAR_OUT_SENSOR_PFCM1 = 0x82E9
    VAR_OUT___25 = 0x82ED
    VAR_OUT_HIGH_OVERLOAD_DETECT = 0x82F5
    VAR_OUT___26 = 0x82F6
    VAR_OUT_SENSOR_SUCTION3_1SEC = 0x82F9
    VAR_OUT_LOAD_EVI_SOL_EEV = 0x82FC
    VAR_OUT___27 = 0x82FD
    VAR_OUT_SENSOR_WATER_PRESSURE = 0x82FE
    LVAR_OUT___ = 0x8401
    LVAR_OUT___1 = 0x8404
    NASA_OUTDOOR_COMP1_RUNNING_TIME = 0x8405
    NASA_OUTDOOR_COMP2_RUNNING_TIME = 0x8406
    LVAR_OUT___2 = 0x8408
    LVAR_OUT___3 = 0x8409
    LVAR_OUT_AUTO_INSPECT_RESULT0 = 0x840B
    LVAR_OUT_AUTO_INSPECT_RESULT1 = 0x840C
    NASA_OUTDOOR_COMP3_RUNNING_TIME = 0x840E
    NASA_OUTDOOR_CONTROL_WATTMETER_1UNIT = 0x8411
    NASA_OUTDOOR_CONTROL_WATTMETER_1UNIT_ACCUM = 0x8412
    LVAR_OUT_CONTROL_WATTMETER_1W_1MIN_SUM = 0x8413
    NASA_OUTDOOR_CONTROL_WATTMETER_ALL_UNIT_ACCUM = 0x8414
    NASA_OUTDOOR_CONTROL_WATTMETER_TOTAL_SUM = 0x8415
    NASA_OUTDOOR_CONTROL_WATTMETER_TOTAL_SUM_ACCUM = 0x8416
    NASA_OUTDOOR_VARIABLE_SETUP_INFO = 0x8417
    LVAR_OUT___4 = 0x841A
    LVAR_OUT___5 = 0x841F
    UNKNOWN = 0x8601
    STR_OUT___ = 0x8608
    STR_OUT_BASE_OPTION = 0x860A
    STR_OUT___1 = 0x860C
    NASA_OUTDOOR_MODELINFORMATION = 0x860D
    NASA_OUTDOOR_SETUP_INFO = 0x860F
    STR_OUT_REF_CHECK_INFO = 0x8613
    RE_1 = 0x4090
    RE_2 = 0x40B2
    NASA_DHW_3WAY_DIR = 0x408B


class Buffer:
    def __init__(self, size=0):
        self.size = size
        self.data = bytearray(size)


class MessageSet:
    def __init__(self, message_number: MessageNumber):
        self.message_number = message_number
        self.type = MessageSetType((message_number.value & 1536) >> 9)
        self.value: Union[int, Buffer] = 0
        self.size = 2

    @staticmethod
    def decode(data: bytes, index: int, capacity: int) -> ("MessageSet", Exception):
        message_number = MessageNumber(int.from_bytes(data[index:index + 2], "big"))
        set_instance = MessageSet(message_number)

        try:
            if set_instance.type == MessageSetType.ENUM:
                set_instance.size = 3
                set_instance.value = data[index + 2]

            elif set_instance.type == MessageSetType.VARIABLE:
                set_instance.size = 4
                set_instance.value = int.from_bytes(data[index + 2:index + 4], "big")

            elif set_instance.type == MessageSetType.LONG_VARIABLE:
                set_instance.size = 6
                set_instance.value = int.from_bytes(data[index + 2:index + 6], "big")

            elif set_instance.type == MessageSetType.STRUCTURE:
                if capacity != 1:
                    print(f"Error: structure messages can only have one message but is {capacity}")
                    return set_instance

                set_instance.size = len(data) - index - 3  # 3=end bytes
                buffer = Buffer(set_instance.size - 2)
                buffer.data[:] = data[index + 2:index + set_instance.size]
                set_instance.value = buffer

            else:
                print("Error: Unknown type")
        except Exception as e:
            print(f'failed to decode message: {e}')
            return set_instance, e

        return set_instance, None

    def __repr__(self):
        value_repr = self.value
        if isinstance(self.value, Buffer):
            value_repr = f"Buffer(size={len(self.value.data)}, data={self.value.data.hex().upper()})"
        return (f"MessageSet(message_number={self.message_number.name} (0x{self.message_number.value:04X}), "
                f"type={self.type.name}, value={value_repr}, size={self.size})")


class PacketType(Enum):
    StandBy = 0
    Normal = 1
    Gathering = 2
    Install = 3
    Download = 4


class DataType(Enum):
    Undefined = 0
    Read = 1
    Write = 2
    Request = 3
    Notification = 4
    Response = 5
    Ack = 6
    Nack = 7


class Address:
    size = 3

    def __init__(self):
        self.klass = None  # AddressClass equivalent
        self.channel = 0
        self.address = 0

    def decode(self, data: bytes, index: int):
        self.klass = f"{data[index]:02X}"
        self.channel = f"{data[index + 1]:02X}"
        self.address = f"{data[index + 2]:02X}"

    def encode(self, data: List[int]):
        data.extend([self.klass, self.channel, self.address])

    def __str__(self):
        return f"Address({self.klass}.{self.channel}.{self.address})"


class Command:
    size = 3

    def __init__(self):
        self.packet_information = True
        self.protocol_version = 2
        self.retry_count = 0
        self.packet_type = PacketType.StandBy
        self.data_type = DataType.Undefined
        self.packet_number = 0

    def decode(self, data: bytes, index: int):
        byte = data[index]
        self.packet_information = ((byte & 128) >> 7) == 1
        self.protocol_version = (byte & 96) >> 5
        self.retry_count = (byte & 24) >> 3
        self.packet_type = PacketType((data[index + 1] & 240) >> 4)
        self.data_type = DataType(data[index + 1] & 15)
        self.packet_number = data[index + 2]

    def encode(self, data: List[int]):
        byte1 = (int(self.packet_information) << 7) | (self.protocol_version << 5) | (self.retry_count << 3)
        byte2 = (self.packet_type.value << 4) | self.data_type.value
        data.extend([byte1, byte2, self.packet_number])

    def __str__(self):
        # return (f"PacketInformation: {self.packet_information}\n"
        #         f"ProtocolVersion: {self.protocol_version}\n"
        #         f"RetryCount: {self.retry_count}\n"
        #         f"PacketType: {self.packet_type}\n"
        #         f"DataType: {self.data_type}\n"
        #         f"PacketNumber: {self.packet_number}")
        return f"DataType: {self.data_type:<10} PacketNumber: {self.packet_number:03d}"


class DecodeResult(Enum):
    InvalidStartByte = 1
    UnexpectedSize = 2
    SizeDidNotMatch = 3
    InvalidEndByte = 4
    CrcError = 5
    Success = 6
    Failure = 7