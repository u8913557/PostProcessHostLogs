
import re
import sys
import argparse
import subprocess
import os
import warnings
import pickle
import time
import argparse
#import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker



LOG_VERB  = '0' # -vvvvv
LOG_INFO  = '1' # -vvvv
LOG_WARN  = '2' # -vvv
LOG_ERR   = '3' # -vv
LOG_CRIT  = '4' # -v
LOG_ALWAYS= '5'
field_index=0

verbose = 2
log_mask = 2
graphical_enable = 0
prev_log_mask = log_mask

def get_logmask(level):
    mask=10
    if(level=="-v"):
        mask=4
    elif(level=="-vv"):
        mask=3
    elif(level=="-vvv"):
        mask=2
    elif(level=="-vvvv"):
        mask=1
    elif(level=='-vvvvv'):
        mask=0
    else:
        mask=2
    return mask

def get_reasoncode(reason):
    reason_code="NA"
    if(reason==0):
        reason_code="WLAN_LOG_REASON_CODE_UNUSED"
    if(reason==1):
        reason_code="WLAN_LOG_REASON_ROAM_FAIL"
    if(reason==2):
        reason_code="WLAN_LOG_REASON_DATA_STALL"
    if(reason==3):
        reason_code="WLAN_LOG_REASON_SME_COMMAND_STUCK"
    if(reason==4):
        reason_code="WLAN_LOG_REASON_QUEUE_FULL"
    if(reason==5):
        reason_code="WLAN_LOG_REASON_POWER_COLLAPSE_FAIL"
    if(reason==6):
        reason_code="WLAN_LOG_REASON_MALLOC_FAIL"
    if(reason==7):
        reason_code="WLAN_LOG_REASON_VOS_MSG_UNDER_RUN"
    if(reason==8):
        reason_code="WLAN_LOG_REASON_HDD_TIME_OUT"
    if(reason==9):
        reason_code="WLAN_LOG_REASON_SME_OUT_OF_CMD_BUF"
    if(reason==10):
        reason_code="WLAN_LOG_REASON_NO_SCAN_RESULTS"
    if(reason==11):
        reason_code="WLAN_LOG_REASON_SCAN_NOT_ALLOWED"
    if(reason==12):
        reason_code="WLAN_LOG_REASON_HB_FAILURE"
    if(reason==13):
        reason_code="WLAN_LOG_REASON_ROAM_HO_FAILURE"
    if(reason==14):
        reason_code="WLAN_LOG_REASON_DISCONNECT"
    return reason_code


def get_data_stall_type(value):
    type="NA"
    if(value==0):
        type="DATA_STALL_LOG_NONE"
    if(value==1):
        type="DATA_STALL_LOG_FW_VDEV_PAUSE"
    if(value==2):
        type="DATA_STALL_LOG_HWSCHED_CMD_FILTER"
    if(value==3):
        type="DATA_STALL_LOG_HWSCHED_CMD_FLUSH"
    if(value==4):
        type="DATA_STALL_LOG_FW_RX_REFILL_FAILED"
    if(value==5):
        type="DATA_STALL_LOG_FW_RX_FCS_LEN_ERROR"
    if(value==6):
        type="DATA_STALL_LOG_FW_WDOG_ERRORS"
    if(value==7):
        type="DATA_STALL_LOG_BB_WDOG_ERROR"
    if(value==8):
        type="DATA_STALL_LOG_HOST_STA_TX_TIMEOUT"
    if(value==9):
        type="DATA_STALL_LOG_HOST_SOFTAP_TX_TIMEOUT"
    if(value==10):
        type="DATA_STALL_LOG_HOST_SOFTAP_TX_TIMEOUT"
    return type


def get_recovery_type(value):
    type="NA"
    if(value==0):
        type="WLAN_DBG_DATA_STALL_RECOVERY_NONE"
    if(value==1):
        type="WLAN_DBG_DATA_STALL_RECOVERY_CONNECT_DISCONNECT"
    if(value==2):
        type="WLAN_DBG_DATA_STALL_RECOVERY_CONNECT_MAC_PHY_RESET"
    if(value==3):
        type="WLAN_DBG_DATA_STALL_RECOVERY_CONNECT_PDR"
    if(value==4):
        type="WLAN_DBG_DATA_STALL_RECOVERY_CONNECT_SSR"
    return type

def field_index_incr():
    global field_index
    field_index = field_index + 1
    return field_index


use_color = True
print_lineno  = True


def get_timestamp(line):
  #[cds_mc_thread][1161015924482] [11:16:02.618724]
  m=re.search("(\]\[(\d+)\]\s\[)", line)
  if m:
        return int(m.group(2))
  else :
        return 0
def get_utctimestamp(line):
  #] [15:34:21.888391] 
  m=re.search("(\]\s\[(.*)\]\swlan\:)", line)
  if m:
        return (m.group(2))
  else :
        return None

force_isf_txt = True
time_stamp_format = 99 # 99 = auto_detect
try:
	#import termcolor 
	import colorama
except ImportError:
	print ("can't import colorama. use 'python -m pip install --upgrade colorama'. use monochorme now")
	use_color = False

if(use_color):
	colorama.init(autoreset=True)
def to_ms(time_string):
    ms_time = 0
    if(time_stamp_format != 4):
        #00:09:13.675
        """
        TBD
        values = print ("  %s" %time_string)
        """
        try:
                ms_time = (int(values[0]) * 3600 + int(values[1]) * 60 + float(values[2])) * 1000
        except:
                #DebugMsg values
                pass
    elif (time_stamp_format == 4):
        ms_time = int(time_string)/19200
    #DebugMsg ms_time
    return ms_time
	
def time_diff_ms(time1,time2):
    ret = (to_ms(time1) - to_ms(time2))/1.0
    return ret

def time_diff_sec(time1,time2):
    ret = (to_ms(time1) - to_ms(time2))/1.0
    return ret
last_log_time = ""
last_time_stamp = ""
scan_started=0
reqtype=""
scantype=""
temp_bssid_hint=0
raw_scan=0

log_header = False
mac_addr=""
#Log Print
#
#
#def LogMsg(log_level,msg,line_no=0,time_stamp='0',Fore='white',Sty='normal'):
def LogMsg(log_level,msg,line_no=0,time_stamp='0',Fore='white',Sty='normal'):
    global last_log_time
    global log_mask
    global log_header 
    global time_stamp_format
    if int(log_level) < log_mask:
        return

    if (log_header == False):
        log_header = True
        print ("-------------------------------------------------------------------------------")

    #Fore: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
    #Back: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
    #Style: DIM, NORMAL, BRIGHT, RESET_ALL

    if(use_color == True):
            
        if time_stamp != '0':
            if (print_lineno == True):
                if (line_no != 0):
                    print (eval("colorama.Fore." + Fore.upper() + "+colorama.Style." + Sty.upper()) + ("#%d:- [ %s ]  %s") % (line_no, time_stamp, msg))
                        
                else:
                    print (eval("colorama.Fore." + Fore.upper() + "+colorama.Style." + Sty.upper()) + ("%s") % ( msg))
            else:
                    print (eval("colorama.Fore." + Fore.upper() + "+colorama.Style." + Sty.upper()) + ("%.12s  %s") % (time_stamp, msg))
        else:
            if (print_lineno == True):
                if (line_no != 0):
                    print (eval("colorama.Fore." + Fore.upper() + "+colorama.Style." + Sty.upper()) + ("#%d:- %s") % (line_no, msg))
                else:
                    print (eval("colorama.Fore." + Fore.upper() + "+colorama.Style." + Sty.upper()) + ("%s") % (msg))

            else:		
                    print (eval("colorama.Fore." + Fore.upper() + "+colorama.Style." + Sty.upper()) + ("%s") % (msg))
                    
    else:
        if time_stamp != '0':
            if (print_lineno == True):
                if (line_no != 0):
                    print ("#%08d:- [%.12s] %s"% (line_no, time_stamp,   msg))
                else:
                        print("%.12s %s" % (time_stamp,  msg))
            else:
                    print("%.12s %s" % (time_stamp,  msg))
        else:
            if (print_lineno == True):
                if (line_no != 0):
                    print("%08d:- %s" % (line_no, msg))
                else:
                        print(msg)

            else:
                print (msg)
                


scan_req_count = []
dbs_enabled=0
HW_info=[]
HW_details_idx=0
scan_times=[]
BSS_Arr=[]
candidate_mac=[]

#Connection params
connection_times=[]
connect_cnts=[]
BSSID=""

#Dictionaries
peer_info={}
DUT_info={}
scan_info={}
scan_history={}


def smallest_num_in_list( list ):
    min = list[ 0 ]
    for a in list:
        if a < min:
            min = a
    return min

def largest_num_in_list( list ):
    max = list[ 0 ]
    for a in list:
        if a > max:
            max = a
    return max

def initialize_dictionaries():
    global peer_info
    global DUT_info
    global scan_info
    global scan_history
    peer_info={'BSSID': [], 'SSID': [], 'channel': [], 'STATE': "DISCONNECTED_STATE", 'vdev_id': [], 'associd': [], 'peer_flags': [], 'rate_caps': [], 'peer_caps': [], 'listen_intval': [], 'ht_caps': [], 'max_mpdu': [], 'nss': [], 'phymode': [], 'peer_mpdu_density': [], 'peer_vht_caps': [], 'RSSI_array': [], 'rate_array': [], 'disconnect_rssi': ""}
    scan_info={'Device_mode': [], 'Channel_List': [], 'Channels': [], 'scan_id': 0, 'time': [], 'BSS': []}
    scan_history={'scan_id': [], 'BSS': [], 'scan_time' :[] }
    #Initilize 
    if "scan_id" not in scan_history:
        scan_history["scan_id"] = []
    if "BSS" not in scan_history:
        scan_history["BSS"] = []
    if "raw_BSS" not in scan_history:
        scan_history["raw_BSS"] = []
    if "scan_time" not in scan_history:
        scan_history["scan_time"] = []
    #Initilize 
    if "RSSI_array" not in peer_info:
        peer_info["RSSI_array"] = []
    if "rate_array" not in peer_info:
        peer_info["rate_array"] = []

    if "MAC" not in DUT_info:
        DUT_info["MAC"]=""
    if "DBS" not in DUT_info:
        DUT_info["DBS"]=""
    if "minChnTime" not in DUT_info:
        DUT_info["minChnTime"]="40"
    if "maxChnTime" not in DUT_info:
        DUT_info["maxChnTime"]="60"
    if "CC" not in DUT_info:
        DUT_info["CC"]=[]

def get_state():
    global peer_info
    return peer_info["STATE"]

def set_state(state):
    global peer_info
    peer_info["STATE"]=state;


'''
def get_Txstatus(value):
    tx_status=0
'''


def get_roam_op_reason(value):
    reason="NA"
    if(value==1):
        reason="SIR_ROAM_SYNCH_PROPAGATION"
    if(value==2):
        reason="SIR_ROAMING_DEREGISTER_STA"
    if(value==3):
        reason="SIR_ROAMING_START"
    if(value==4):
        reason="SIR_ROAMING_ABORT"
    if(value==5):
        reason="SIR_ROAM_SYNCH_COMPLETE"
    if(value==6):
        reason="SIR_ROAM_SYNCH_NAPI_OFF"
    if(value==7):
        reason="SIR_ROAMING_INVOKE_FAIL"
    return reason


def get_connection_status(value):
    RoamResult="NA"
    if(value==0):
        RoamResult="eCSR_ROAM_RESULT_SUCCESS"
    if(value==1):
        RoamResult="eCSR_ROAM_RESULT_FAILURE"
    if(value==2):
        RoamResult="eCSR_ROAM_RESULT_ASSOCIATED"
    if(value==3):
        RoamResult="eCSR_ROAM_RESULT_NOT_ASSOCIATED"
    if(value==4):
        RoamResult="eCSR_ROAM_RESULT_MIC_FAILURE"
    if(value==5):
        RoamResult="eCSR_ROAM_RESULT_FORCED"
    if(value==6):
        RoamResult="eCSR_ROAM_RESULT_DISASSOC_IND"
    return RoamResult

def get_subType(value):
    subType="NA"

    if(value=="0"):
        subType="AssocReq"
    if(value=="1"):
        subType="AssocRes"
    if(value=="2"):
        subType="ReassocReq"
    if(value=="4"):
        subType="ProbeReq"
    if(value=="5"):
        subType="ProbeRes"
    if(value=="10"):
        subType="Dis-assoc"
    if(value=="11"):
        subType="Auth"
    if(value=="12"):
        subType="De-Auth"
    if(value=="13"):
        subType="Action"
    return subType
PatternValuePair_raw = (
    #wma_set_linkstate: state 1 selfmac c4:ab:b2:3d:41:8e
    ('wma_set_linkstate',[r'.+?\sselfmac\s(?P<mac_address>.*)',1,1,1]),
    #####
    ####   Scan
    ###
    ##

    #__wlan_hdd_cfg80211_scan: 1905: enter
    #__wlan_hdd_cfg80211_scan: 1942: Device_mode QDF_STA_MODE(0)
    #__wlan_hdd_cfg80211_scan: 2182: Channel-List: 1 2 3 4 5 6 7 8 9 10 11 12 13 36 40 44 48 52 56 60 64 149 153 157 161 165 
    #__wlan_hdd_cfg80211_scan: 2183: No. of Scan Channels: 26
    #__wlan_hdd_cfg80211_scan: 2321: requestType 2, scanType 1, minChnTime 20, maxChnTime 40,p2pSearch 0, skipDfsChnlIn P2pSearch 0
    ('__wlan_hdd_cfg80211_scan',[r'.+?\senter(?P<scan_started>)|.+?\sDevice_mode\s(?P<Device_mode>.*)|.+?\-List\:\s(?P<Channel_List>.*)|.+?\sChannels\:\s(?P<Channels>\d+)|.+?\srequestType\s(?P<requestType>\d+).+?\sscanType\s(?P<scanType>\d+).+?\sminChnTime\s(?P<minChnTime>\d+).+?\smaxChnTime\s(?P<maxChnTime>\d+).+?p2pSearch\s(?P<p2pSearch>\d+)',2,1,1]),
    #csr_queue_sme_command: 19804: scan pending list count 0 scan_id 40961
    ('csr_queue_sme_command',[r'.+?\sscan_id\s(?P<scan_id>\d+)',3,1,1]),
    #csr_release_scan_command: 6264: Remove Scan command reason = 9, scan_id 40966
    ('csr_release_scan_command',[r'.+?\sscan_id\s(?P<scan_id>\d+)',4,1,1]),
    #11:16:47.710956  R0: [cds_mc_thread][1161881568427] [11:16:47.704346] wlan: [23163:IL:HDD] hdd_cfg80211_scan_done_callback: 1304: exit
    ('hdd_cfg80211_scan_done_callback',[r'.+?\sexit',5,1,1]),
    #11:27:07.336091  R0: [cds_mc_thread][1173778424185] [11:27:07.332250] wlan: [23163:I :HDD] hdd_cfg80211_scan_done_callback: 1237: NO SCAN result
    ('hdd_cfg80211_scan_done_callback',[r'.+?\sNO\sSCAN\sresult',6,1,1]),
    #8037 11:16:07.365615  R0: [cds_mc_thread][1161107049597] [11:16:07.364824] wlan: [23163:I :SME] csr_scan_get_result: 2238: return 0 BSS 89
    ('csr_scan_get_result',[r'.+?\sBSS\s(?P<BSS>\d+)',7,1,1]),
    #11:16:05.264082  R0: [cds_mc_thread][1161066696614] [11:16:05.263106] wlan: [23163:I :PE ] lim_process_probe_rsp_frame: 159: Probe Resp Frame Received: BSSID 70:df:2f:b6:ea:0e (RSSI 53) 
    ('lim_process_probe_rsp_frame',[r'.+?\sBSSID\s(?P<BSSID>.*).+?RSSI\s(?P<RSSI>\d+)',8,1,1]),
    #23:02:11.034640  R0: [wificond][1046522964] [23:02:11.031674] wlan: [1151:IL:HDD] __wlan_hdd_cfg80211_sched_scan_start: 3187: enter
    #23:02:11.034648  R0: [wificond][1046523904] [23:02:11.031721] wlan: [1151: D:HDD] __wlan_hdd_cfg80211_sched_scan_start: 3339: Channel-List: 1 2 3 4 5 6 7 8 9 10 11 36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144 149 153 157 161 165  
    #23:02:11.034656  R0: [wificond][1046524051] [23:02:11.031729] wlan: [1151: D:HDD] __wlan_hdd_cfg80211_sched_scan_start: 3401: Number of hidden networks being Configured = 2
    #23:02:11.034671  R0: [wificond][1046524313] [23:02:11.031742] wlan: [1151: D:HDD] __wlan_hdd_cfg80211_sched_scan_start: 3429: Base scan interval: 20 sec PNOScanTimerRepeatValue: 30
    ('__wlan_hdd_cfg80211_sched_scan_start',[r'.+?\senter|.+?\sChannel-List\:\s(?P<Channel_List>.*)|.+?\shidden\snetworks\s.+?\=\s(?P<hidde_networks>.*)|.+?\sscan\sinterval\:\s(?P<base_scan>\d+).+?\sPNOScanTimerRepeatValue\:\s(?P<PNOScanTimerRepeatValue>\d+)',9,1,1]),
    #23:07:55.003334  R0: [wificond][7650747983] [23:07:55.001726] wlan: [1151:IL:HDD] __wlan_hdd_cfg80211_sched_scan_stop: 3579: enter(wlan0)
    ('__wlan_hdd_cfg80211_sched_scan_stop',[r'.+?\senter',10,1,1]),
    #<6>[ 2832.580795] (2)[1985:cds_mc_thread]R0: [cds_mc_thread][54465337197] [20:07:38.422864] wlan: [1985:E :SME] csr_scan_active_list_timeout_handle: 8266: Scan Timeout:Sending abort to Firmware ID 40966 session 0
    ('csr_scan_active_list_timeout_handle',[r'.+?\sabort\sto\sFirmware\sID\s(?P<scan_id>\d+)',11,1,1]),
    #10:36:12.391667  R0: [cds_mc_thread][1400763867514] [10:36:12.376748] wlan: [1859: D:SME] _csr_calculate_bss_score: 1871: BSSID:20:6b:e7:83:50:04 rssi=-78 htcaps=1 vht=0 bw=1 channel=1 beamforming=0 ap_load=0 est_air_time_percentage=0 pcl_score 0 Final Score 3520 ap_NSS 3 nss 2 dot11mode 7 is_vht 1
    ('_csr_calculate_bss_score',[r'.+?\sBSSID(.*).+?\sbeamforming(.*)',12,1,1]),
    #10:36:11.101223  R0: [wificond][1400738502276] [10:36:11.055641] wlan: [1217: D:QDF] cds_is_connection_in_progress: 2918: 0000000000000000(0) Connection is in progress
    #('cds_is_connection_in_progress',[r'.+?\sConnection\sis\sin\progress',13,1,1]),
    ('cds_is_connection_in_progress',[r'.+?\sprogress|.+?\sexchange',13,1,1]),
    #10:37:41.430100  R0: [cds_mc_thread][1402472551955] [10:37:41.370729] wlan: [1859: D:PE ] lim_process_abort_scan_ind: 1215: scan_id 42525, scan_requestor_id 0xa000
    #10:15:31.553810  R0: [wpa_supplicant][1376935609329] [10:15:31.321634] wlan: [2605: D:SME] csr_send_scan_abort: 7253: Abort scan sent to Firmware scan_id 42314 session 0
    #('lim_process_abort_scan_ind',[r'.+?\sscan_id\s(?P<scan_id>\d+)',14,1,1]),
    ('csr_send_scan_abort',[r'.+?\sscan_id\s(?P<scan_id>\d+)',14,1,1]),

    


    #####
    ####   connection
    ###    idx starting from 15
    ##
    #11:16:05.239647  R0: [wpa_supplicant][1161066234781] [11:16:05.239053] wlan: [23177:IL:HDD] __wlan_hdd_cfg80211_connect: 13794: enter
    ('__wlan_hdd_cfg80211_connect',[r'.+?\senter',15,1,1]),
    #19:32:16.581127  R0: [wpa_supplicant][5280183269] [19:32:16.579572] wlan: [2988: D:HDD] wlan_hdd_cfg80211_connect_start: 15359: bssid_hint is given by upper layer 00:01:02:03:04:05
    #19:32:16.581131  R0: [wpa_supplicant][5280183339] [19:32:16.579576] wlan: [2988: D:HDD] wlan_hdd_cfg80211_connect_start: 15365: Connect to SSID: CMW-AP operating Channel: 0
    ('wlan_hdd_cfg80211_connect_start',[r'bssid.+?\slayer\s(?P<BSSID>.*)|.+?\SSID:\s(?P<SSID>.*)\soperating.+?\:\s(?P<Channel>\d+)',16,1,1]),
    #('wlan_hdd_cfg80211_connect_start',[r'bssid.+?\slayer\s(?P<BSSID>.*)|.+?\sSSID\:(?P<SSID>.*).+?\sChannel\:(?P<Channel>\d+)',16,1,1]),

    #10:06:32.445882  R0: [cds_mc_thread][945468863941] [10:06:32.437100] wlan: [1633: D:WMA] TX MGMT - Type 0, SubType 11 seq_num[2122]
    ('TX MGMT - Type',[r'.+?\sSubType\s(?P<SubType>\d+)\sseq_num(?P<seq_num>\[(\d+)\])',20,1,1]),
    #10:06:11.671989  R0: [cds_mc_thread][945070155384] [10:06:11.671029] wlan: [1633: D:PE ] lim_handle80211_frames: 936: RX MGMT - Type 0, SubType 11, seq num[439]
    #('lim_handle80211_frames',[r'.+?\sSubType\s(?P<SubType>\d+).+?\snum(\[?P<seq_num>(\d+)\])',21,1,1]),
    ('lim_handle80211_frames',[r'.+?\sSubType\s(?P<SubType>\d+).+?\[(?P<seq_num>\d+)',21,1,1]),
    #11:16:17.798704  R0: [cds_mc_thread][1161306737117] [11:16:17.765215] wlan: [23163:IH:HDD] hdd_sme_roam_callback: 4768: ****eCSR_ROAM_ASSOCIATION_COMPLETION****
    #19:37:42.424730  R0: [cds_mc_thread][11535795036] [19:37:42.392685] wlan: [5865: D:HDD] hdd_sme_roam_callback: 4875: ****eCSR_ROAM_DISASSOCIATED****
    ('hdd_sme_roam_callback',[r'.+?\s\*\*\*\*(?P<ASSOC_STATUS>.*)\*\*\*\*',22,1,1]),
    #19:36:30.984881  R0: [cds_mc_thread][10164517325] [19:36:30.971971] wlan: [5865: D:WMI] send_peer_assoc_cmd_tlv: vdev_id 0 associd 1 peer_flags 201002 rate_caps 8 peer_caps 401 listen_intval 1 ht_caps c max_mpdu 65535 nss 1 phymode 5 peer_mpdu_density 0 cmd->peer_vht_caps 0
    #('send_peer_assoc_cmd_tlv',[r'.+?\svdev_id\s(?P<vdev_id>\d+)\sassocid\s(?P<associd>\d+)',23,1,1]),
    #('send_peer_assoc_cmd_tlv',[r'.+?\svdev_id\s(?P<vdev_id>\d+)\sassocid\s(?P<associd>\d+)\speer_flags\s(?P<peer_flags>\d+)\srate_caps\s(?P<rate_caps>\d+)\slisten_intval\s(?P<listen_intval>\d+)\sht_caps\s(?P<ht_caps>\d+)\smax_mpdu\s(?P<max_mpdu>\d+)\snss\s(?P<nss>\d+)\sphymode\s(?P<phymode>\d+)\speer_mpdu_density\s(?P<peer_mpdu_density>\d+).+?peer_vht_caps\s(?P<peer_vht_caps>\d+)',23,1,1]),
    ('send_peer_assoc_cmd_tlv',[r'.+?\svdev_id\s(?P<vdev_id>\d+)\sassocid\s(?P<associd>\d+)\speer_flags\s(?P<peer_flags>.*)\srate_caps\s(?P<rate_caps>.*)\speer_caps\s(?P<peer_caps>.*)\slisten_intval\s(?P<listen_intval>\d+)\sht_caps\s(?P<ht_caps>.*)\smax_mpdu\s(?P<max_mpdu>\d+)\snss\s(?P<nss>\d+)\sphymode\s(?P<phymode>\d+)\speer_mpdu_density\s(?P<peer_mpdu_density>\d+).+?peer_vht_caps\s(?P<peer_vht_caps>\d+)',23,1,1]),
    #17:29:31.449191  R0: [cds_mc_thread][1307968374678] [17:29:31.442454] wlan: [2223: D:PE ] lim_add_sta_self: 2851: sessionid: 0  Assoc ID: 2 listenInterval = 1 shortPreambleSupported: 1
    ('lim_add_sta_self',[r'.+?\sAssoc\sID\:\s(?P<aid>\d+)\slistenInterval',23,1,2]),

    #19:37:12.376803  R0: [cds_mc_thread][10959425206] [19:37:12.373423] wlan: [5865: D:PE ] lim_process_switch_channel_join_req: 3006: Sessionid: 0 Send Probe req on channel 6 ssid:CMW-AP BSSID: 00:01:02:03:04:05
    ('lim_process_switch_channel_join_req',[r'.+?\sSend\sProbe\sreq\son\schannel\s(?P<channel>\d+)\sssid\:(?P<ssid>.*)\sBSSID\:\s(?P<BSSID>.*)',24,1,1]),
    #14:52:16.786444  R0: [cds_mc_thread][1487096846897] [14:52:16.727159] wlan: [3265: D:PE ] lim_populate_mac_header: 178: seqNumLo=5, seqNumHi=130, mgmtSeqNum=2085
    ('lim_populate_mac_header',[r'.+?\smgmtSeqNum\=(?P<SN>\d+)',24,1,2]),

    #19:33:42.923495  R0: [cds_mc_thread][6937927990] [19:33:42.920443] wlan: [5865: D:WMA] wma_process_mgmt_tx_completion: status: 2 wmi_desc_id: 1
    ('wma_process_mgmt_tx_completion',[r'.+?\sstatus\:\s(?P<tx_status>\d+)',25,1,1]),
    #11:14:03.548545  R0: [cds_mc_thread][66713152360] [11:14:03.514125] wlan: [1805: D:HDD] hdd_association_completion_handler: 2764: sending connect indication to nl80211:for bssid 20:6b:e7:83:50:04 result:2 and Status:7
    #19:34:50.912035  R0: [cds_mc_thread][8243164106] [19:34:50.901491] wlan: [5865:E :HDD] hdd_association_completion_handler: 2896: wlan: connection failed with 00:01:02:03:04:05 result: 3 and Status: 7
    ('hdd_association_completion_handler',[r'.+?\sresult\:(?P<sucess_status>\d+).*|.+?\sconnection\sfailed.*\sresult\:\s(?P<fail_status>\d+)',26,1,1]),
    #11:16:00.490343  R0: [cds_mc_thread][1160974885032] [11:16:00.481253] wlan: [18734:IH:HDD] hdd_lost_link_info_cb: 1186: rssi on disconnect -71
    ('hdd_lost_link_info_cb',[r'.+\sdisconnect(?P<disconnect_rssi>.*)',27,1,1]),
    #15:06:44.505305  R0: [cds_mc_thread][46723330859] [15:06:44.487421] wlan: [2276: D:QDF] cds_dump_current_concurrency: 3282: SAP+STA DBS
    ('cds_dump_current_concurrency',[r'.+?\s\d+\:\s(?P<concurrency>.*)',28,1,1]),
    #14:35:16.039672  R0: [wificond][28865408263] [14:35:16.024732] wlan: [1229: D:HDD] __wlan_hdd_cfg80211_get_station: 4150: RSSI -19, RLMS 1, rate 4330, rssi high -55, rssi mid -65, rssi low -80, rate_flags 0x88, MCS 9
    ('__wlan_hdd_cfg80211_get_station',[r'.+?\sRSSI\s(?P<RSSI>[-+]?[0-9]+)\,.*\srate\s(?P<rate>\d+)',29,1,1]),
    #15:06:52.280606  R0: [cds_mc_thread][46872824952] [15:06:52.273572] wlan: [2276: D:PE ] lim_get_min_session_txrate: 7466: supported min_rate: 2(2)
    ('lim_get_min_session_txrate',[r'.+?\smin_rate\:\s(?P<min_rate_h>\d+)\((?P<min_rate>\d+)\)',30,1,1]),
    #15:06:24.833558  R0: [cds_mc_thread][46345827031] [15:06:24.825763] wlan: [2276:E :PE ] lim_process_auth_frame: 1137: auth frame, seq num: 256 is already processed, drop it
    ('lim_process_auth_frame',[r'.+?\sseq\snum\:\s(?P<SN>\d+)',31,1,1]),
    #19:35:07.578111  R0: [cds_mc_thread][17008394409] [19:35:07.540427] wlan: [1985:I :HDD] hdd_hostapd_sap_event_cb: 1973:  associated d4:1a:3f:00:26:93
    ('hdd_hostapd_sap_event_cb',[r'.+?\sassociated\s(?P<client_mac>.*)',32,1,1]),
    #19:40:26.102378  R0: [cds_mc_thread][23124510756] [19:40:26.088153] wlan: [1985:W :PE ] lim_reject_association: 898: received Re/Assoc req when max associated STAs reached from
    ('lim_reject_association',[r'.+?\smax\sassociated\sSTAs\s(.*)',33,1,1]),
    #11:03:05.067940  R0: [wpa_supplicant][4763620533] [11:03:04.428898] wlan: [2599: D:SME] csr_roam_print_candidate_aps: 8198: BSSID 50:fa:84:31:c5:3c score is 3054
    ('csr_roam_print_candidate_aps',[r'.+?\sBSSID\s(?P<BSSID>.*)\sscore\sis\s(?P<score>\d+)',34,1,1]),
    #17:07:43.230495  R0: [cds_mc_thread][424950728082] [17:07:43.227895] wlan: [1575: D:PE ] sch_beacon_edca_process: 1057: AC[0]:  AIFSN: 3, ACM 0, CWmin 4, CWmax 10, TxOp 0
    ('sch_beacon_edca_process',[r'.+?\sAC(?P<edca_params>.*)',35,1,1]),
    #17:07:43.230602  R0: [cds_mc_thread][424950730675] [17:07:43.228030] wlan: [1575: D:PE ] lim_send_edca_params: 355: AC[0]:  AIFSN 3, ACM 0, CWmin 4, CWmax 10, TxOp 0 
    ('lim_send_edca_params',[r'.+?\sAC(?P<edca_params>.*)',35,1,2]),
    #14:52:42.053144  R0: [cds_mc_thread][395699370515] [14:52:42.049010] wlan: [2307:E :PE ] lim_process_auth_frame_type1: 335: STA is already connected but received auth frame Send the Deauth and lim Delete Station Context staId: 1 associd: 4
    ('lim_process_auth_frame_type1',[r'.+?\salready\sconnected\s(?P<edca_params>.*)',36,1,1]),
    #14:33:44.070809  R0: [cds_mc_thread][373838133557] [14:33:44.054948] wlan: [2307: D:PE ] lim_process_deauth_frame: 165: Received Deauth frame for Addr: e0:c1:43:27:b8:00(mlm state = eLIM_MLM_LINK_ESTABLISHED_STATE, sme state = 11 systemrole = 3 RSSI = -58) with reason code 6 [eSIR_MAC_CLASS2_FRAME_FROM_NON_AUTH_STA_REASON] from 74:ea:cb:35:9d:71
    ('lim_process_deauth_frame',[r'.+?\sreason\scode\s(?P<reason_code>.*)\sfrom\s(?P<BSSID>.*)',37,1,1]),
    #17:42:18.337909 R0: [cds_mc_thread][110033097669] [17:42:18.333080] wlan: [1939: D:PE ] lim_process_disassoc_frame: 162: Received Disassoc frame for Addr: 8e:fd:f0:89:b3:44(mlm state=eLIM_MLM_BSS_STARTED_STATE, sme state=18 RSSI=-33),with reason code 8 [eSIR_MAC_DISASSOC_LEAVING_BSS_REASON] from 40:83:de:c3:6c:e5
    ('lim_process_disassoc_frame',[r'.+?\sreason\scode\s(?P<reason_code>.*)\sfrom\s(?P<BSSID>.*)',37,1,2]),



    


    #19:32:16.597714  R0: [kworker/1:2][5280426056] [19:32:16.592218] wlan: [617: D:WMA] wma_mgmt_rx_process: 3641: BSSID: 00:01:02:03:04:05 snr = 30, rssi = -66, rssi_raw = -66 tsf_delta: 0
    #####
    #### write logic to find RSSI based on BSSID
    ##



    #11:16:00.440594  R0: [wpa_supplicant][1160974089489] [11:16:00.439818] wlan: [18741:IL:HDD] __wlan_hdd_cfg80211_disconnect: 14112: enter
    ('__wlan_hdd_cfg80211_disconnect',[r'.+?\senter',41,1,1]),
    #19:36:48.543804  R0: [cds_mc_thread][10501431053] [19:36:48.519561] wlan: [5865: D:WMA] wma_peer_sta_kickout_event_handler: Enter
    ('wma_peer_sta_kickout_event_handler',[r'.+?\sEnter',42,1,1]),
    #10:48:04.700853  R0: [cds_mc_thread][1731670570387] [10:48:04.695857] wlan: [1922: D:PE ] lim_handle_heart_beat_failure: 501: HB missed from AP. Sending Probe Req
    ('lim_handle_heart_beat_failure',[r'.+?\sHB\smissed\sfrom\sAP',43,1,1]),
    #10:48:04.800764  R0: [cds_mc_thread][1731671778945] [10:48:04.758803] wlan: [1922: D:PE ] lim_handle_heart_beat_failure_timeout: 5575: SME: 11 MLME: 16 HB-Count: 0
    ('lim_handle_heart_beat_failure_timeout',[r'.+?\sSME:\s(\d+)',44,1,1]),
    # 15:09:43.829634  R0: [cds_mc_thread][50166694222] [15:09:43.829263] wlan: [2276:E :QDF] cds_flush_logs: Triggering bug report: type:1, indicator=2 reason_code=14
    ('cds_flush_logs',[r'.+?\sreason_code\=(?P<reason_code>\d+)',45,1,1]),



    ##
    #
    #11:15:58.662042  R0: [wpa_supplicant][1160939937518] [11:15:58.661070] wlan: [18741: D:WMA] wma_is_dbs_enable: DBS=1
    ('wma_is_dbs_enable',[r'.+?\sDBS=(?P<DBS>.*)',50,1,1]),
    #11:16:02.652884  R0: [cds_mc_thread][1161015924822] [11:16:02.618742] wlan: [23163: D:WMA] wma_dump_dbs_hw_mode:[0]-MAC0: tx_ss:2 rx_ss:2 bw_idx:6
    ('wma_dump_dbs_hw_mode',[r'wma_dump_dbs_hw_mode\:\[\d\]\-\.*(.*)',51,1,1]),
    #11:16:02.652991  R0: [cds_mc_thread][1161016539336] [11:16:02.650748] wlan: [23163: D:WMA] WMA <-- WMI_READY_EVENTID
    ('WMI_READY_EVENTID',[r'WMI_READY_EVENTID',52,1,1]),


    ###
    ## Wow
    #
    #07:37:05.275853  R0: [soft_irq][852668327749] [07:37:05.223997] wlan: [0:F :WMA] Non-WLAN triggered wakeup: UNSPECIFIED (-1)
    ('triggered wakeup',[r'.+?WMA\]\s(.*)',61,1,1]),
    #07:25:28.990327  R0: [soft_irq][839299812618] [07:25:28.947167] wlan: [0:F :WMA] uc 414 bc 0 v4_mc 1893 v6_mc 0 ra 0 ns 0 na 0 pno_match 0 pno_complete 0 gscan 0 low_rssi 0 rssi_breach 0 icmp 0 icmpv6 0 oem 0
    ('v4_mc',[r'.+?WMA\]\s(.*)',62,1,1]),
    
    ###
    ## Config
    #
    #23:02:01.341761  R0: [kworker/u16:16][682329081] [03:01:16.725003] wlan: [1104: D:HDD] hdd_cfg_print: 5829: Name = [RTSThreshold] Value = 1048576
    ('hdd_cfg_print',[r'.+?\sName\s\=\s(?P<config>.*)',81,1,1]),

    ###
    ## Country
    #
    #23:02:01.384872  R0: [android.hardwar][750006043] [21:57:36.669783] wlan: [749: D:SME] csr_init_operating_classes: 20396: Current Country = US
    ('csr_init_operating_classes',[r'.+?\sCountry\s\=\s(?P<CC>.*)',91,1,1]),
    #10:13:22.379658  R0: [cds_mc_thread][1374458746782] [10:13:22.318377] wlan: [1859: D:SME] csr_set_cfg_country_code: 6955: Setting Country Code in Cfg CN
    ('csr_set_cfg_country_code',[r'.+?\sCfg\s(?P<CC>.*)',91,1,1]),

    #23:08:25.722196  R0: [cds_mc_thread][8240539042] [23:08:25.720009] wlan: [1584: D:WMI] Send WMI command:WMI_VDEV_SET_PARAM_CMDID command_id:20488 htc_tag:0
    ('Send WMI command',[r'.+?\sWMI\scommand\:(?P<CMD>.*)\scommand_id\:(?P<id>\d+)',92,1,1]),
    #('Send WMI command',[r'.+?\sSend\s(.*)',92,1,1]),

    ###
    ## Roaming
    #
    #12:23:00.991381  R0: [cds_mc_thread][3554662988] [12:23:00.960645] wlan: [3139: D:SME] csr_process_roam_sync_callback: 21111: LFR3: reason: 3
    ('csr_process_roam_sync_callback',[r'.+?\sLFR3\:\sreason\:\s(?P<reason>\d+)',101,1,1]),
    #12:23:01.019780  R0: [cds_mc_thread][3555644653] [12:23:01.011773] wlan: [3139: D:SME] LFR3:csr_neighbor_roam_indicate_connect
    ('csr_neighbor_roam_indicate_connect',[r'.+?\sLFR3\:csr_neighbor_roam_indicate_connect',102,1,1]),
    #12:23:25.582966  R0: [cds_mc_thread][4026733360] [12:23:25.547643] wlan: [3139: D:WMA] LFR3:wma_add_bss_sta_mode: bssid 70:f3:5a:48:9a:0e staIdx 1
    #('wma_add_bss_sta_mode',[r'.+?\sLFR3:wma_add_bss_sta_mode\:\s\bssid\s(?P<candidate_mac>.*)\sstaIdx',103,1,1]),
    ('wma_add_bss_sta_mode',[r'.+?\sLFR3:wma_add_bss_sta_mode\:\sbssid\s(?P<candidate_mac>.*)\sstaIdx',103,1,1]),

    ###
    ## Data Stall
    #
    #17:37:03.031928  R0: [kworker/3:2][110120957111] [17:37:03.029743] wlan: [8847: D:WMA] data_stall_type: 3 vdev_id_bitmap: 1 reason_code1: 0 reason_code2: 7 recovery_type: 0 
    ('data_stall_type',[r'.+?\sdata_stall_type\:\s(?P<data_stall_type>\d+).+?\sreason_code1\:\s(?P<reason_code1>\d+)\sreason_code2\:\s(?P<reason_code2>\d+)\srecovery_type\:\s(?P<recovery_type>\d+)',111,1,1]),

    )


dut_details=False
def ProcessResults(fileName):
    global dut_details
    global field_index
    global scan_req_count
    global scan_times
    global scan_started
    global BSS_Arr
    global connection_times
    global peer_info
    global DUT_info
    global scan_info
    global scan_history
    global graphical_enable
    global candidate_mac
    global temp_bssid_hint    
    global raw_scan    



    try:
        f = open(fileName, encoding="ISO-8859-1")		
    except IOError:
        print ("File not found!")
        time.sleep(5)
        sys.exit(1)
    line_no=0
    for line in f:
        for pattern in PatternValuePair_raw:
            if pattern[0] in line:
                time_stamp=get_timestamp(line)
                m = re.search(pattern[1][0],line)
                
                if (m == None):
                        continue 
                #print(m.group(0))
                #wma_set_linkstate: state 1 selfmac c4:ab:b2:3d:41:8e
                if(pattern[1][1] == 1):
                    if (dut_details == False):
                        mac_addr = m.group('mac_address')
                        DUT_info.update({"MAC":m.group('mac_address')})
                        dut_details=True 
                        #LogMsg(LOG_WARN, "DUT-MAC %s" % (mac_addr), 0,0, )



                #####
                ###
                ##      scan
                #
                #__wlan_hdd_cfg80211_scan: 1905: enter
                #__wlan_hdd_cfg80211_scan: 1942: Device_mode QDF_STA_MODE(0)
                #__wlan_hdd_cfg80211_scan: 2182: Channel-List: 1 2 3 4 5 6 7 8 9 10 11 12 13 36 40 44 48 52 56 60 64 149 153 157 161 165 
                #__wlan_hdd_cfg80211_scan: 2183: No. of Scan Channels: 26
                #__wlan_hdd_cfg80211_scan: 2321: requestType 2, scanType 1, minChnTime 20, maxChnTime 40,p2pSearch 0, skipDfsChnlIn P2pSearch 0
                elif(pattern[1][1]==2):
                    
                    Device_mode= m.group("Device_mode")
                    requestType=m.group("requestType");
                    scanType=m.group("scanType")
                    minChnTime=m.group("minChnTime");
                    maxChnTime=m.group("maxChnTime")
                    Channel_List=m.group("Channel_List")
                    Channels=m.group("Channels")

                    if Device_mode is not None:
                        scan_info.update({"Device_mode":Device_mode})
                    if Channel_List is not None:
                        scan_info.update({"Channel_List": Channel_List})
                    if Channels is not None:
                        scan_info.update({"Channels": Channels})
                    if minChnTime is not None:
                        DUT_info.update({"scanType":scanType})

                    if requestType is not None and scanType is not None and minChnTime is not None and maxChnTime is not None:
                        scan_info.update({"requestType": requestType})
                        DUT_info.update({"minChnTime": minChnTime})
                        DUT_info.update({"maxChnTime": maxChnTime})
                    scan_started=1					
                    #LogMsg(LOG_WARN, "scan_id=0x%x  scan_completed [Total Scan Time= %d msec, # of BSSIDs=%s]" % ((int(scan_id),(total_Scan_time/19200), BSS_Arr.pop())), line_no, time_stamp, "green", "bright")
                    #sys.exit(1)



                #csr_queue_sme_command: 19804: scan pending list count 0 scan_id 40961
                elif(pattern[1][1]==3):
                    if (scan_started==1):
                        #scan_info.update({"scan_id":m.group("scan_id")})
                        scan_info["scan_id"]=m.group("scan_id")
                        scan_req_count.append(1)
                        scan_info["time"]=(time_stamp)
                        #get_utctimestamp(line)
                        LogMsg(LOG_WARN, "UTC time - %s scan_id 0x%x" %(get_utctimestamp(line), int(scan_info["scan_id"])),  line_no, '0')



                #csr_release_scan_command: 6264: Remove Scan command reason = 9, scan_id 40966
                elif (pattern[1][1] == 4):
                    if (1):
                        if (scan_started==1):
                            scan_started=0
                            scan_start_time= (scan_info["time"])
                            scan_time=(time_stamp -scan_start_time)/19200
                            scan_info["time"]=scan_time
             
                            LogMsg(LOG_ERR, " scan_id=0x%x, Device_mode=%s Channels=%s:%s\n Total Scan time =%.2fmsec, raw_BSSID[ %s ] cahce_BSSID[ %s ]" %(int(scan_info["scan_id"]), scan_info["Device_mode"],scan_info["Channels"], scan_info["Channel_List"],scan_time, scan_info["raw_BSS"], scan_info["BSS"]),  line_no, time_stamp, "green", "bright")
                            if (scan_time >5000) and (int(scan_info["Channels"]) >  6):
                                LogMsg(LOG_ERR, "***********More time(>5sec) for scan*********", 0, 0, "red", "bright")
                            elif (scan_time <500) and (int(scan_info["Channels"]) > 6):
                                LogMsg(LOG_ERR, "***********less time(<500msec) for scan*********", 0, 0, "red", "bright")

                            #LogMsg(LOG_WARN, "\t\t\t#BSSID's found [ %s ]; Total time =%s" %(scan_info["BSS"], scan_info["time"]),  0, 0,"green", "bright")
                    #Clear scan_info disctionary
                    scan_info = {key: 0 for key in scan_info}



                #11:27:07.336091  R0: [cds_mc_thread][1173778424185] [11:27:07.332250] wlan: [23163:I :HDD] hdd_cfg80211_scan_done_callback: 1237: NO SCAN result
                elif(pattern[1][1] == 6) :
                    LogMsg(LOG_ERR, "[0x%x]NO SCAN results" % int(scan_info["scan_id"]), line_no, time_stamp, "red", "bright")
                    #LogMsg(LOG_ERR, "NO SCAN results", line_no, time_stamp, "red", "bright")



                #8037 11:16:07.365615  R0: [cds_mc_thread][1161107049597] [11:16:07.364824] wlan: [23163:I :SME] csr_scan_get_result: 2238: return 0 BSS 89
                elif (pattern[1][1] == 7):
                  
                    if (scan_started==1 ):
                        BSS_Arr.append(m.group("BSS"))
                        scan_info["BSS"]=m.group("BSS")
                        scan_info["raw_BSS"]=raw_scan
                        if(scan_info["scan_id"] != 0):
                            scan_history["scan_id"].append("0x%x" %int(scan_info["scan_id"]))
                            scan_history["BSS"].append(int(scan_info["BSS"]))
                            scan_history["raw_BSS"].append(raw_scan)
                        raw_scan=0
                #11:16:05.264082  R0: [cds_mc_thread][1161066696614] [11:16:05.263106] wlan: [23163:I :PE ] lim_process_probe_rsp_frame: 159: Probe Resp Frame Received: BSSID 70:df:2f:b6:ea:0e (RSSI 53) 
                elif (pattern[1][1] == 8):
                    LogMsg(LOG_INFO, "0x%x: Probe Rsp from= %s (RSSI = %s) " %(int(scan_info["scan_id"]),m.group("BSSID"), m.group("RSSI")),  line_no, time_stamp)
                    if(int(scan_info["scan_id"]) !=0):
                        raw_scan +=1


                #23:02:11.034640  R0: [wificond][1046522964] [23:02:11.031674] wlan: [1151:IL:HDD] __wlan_hdd_cfg80211_sched_scan_start: 3187: enter
                #23:02:11.034648  R0: [wificond][1046523904] [23:02:11.031721] wlan: [1151: D:HDD] __wlan_hdd_cfg80211_sched_scan_start: 3339: Channel-List: 1 2 3 4 5 6 7 8 9 10 11 36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144 149 153 157 161 165  
                #23:02:11.034656  R0: [wificond][1046524051] [23:02:11.031729] wlan: [1151: D:HDD] __wlan_hdd_cfg80211_sched_scan_start: 3401: Number of hidden networks being Configured = 2
                #23:02:11.034671  R0: [wificond][1046524313] [23:02:11.031742] wlan: [1151: D:HDD] __wlan_hdd_cfg80211_sched_scan_start: 3429: Base scan interval: 20 sec PNOScanTimerRepeatValue: 30
                elif (pattern[1][1] == 9):
                    #print(m.group(0))
                    if m.group("Channel_List") is not None:
                        LogMsg(LOG_INFO, " __wlan_hdd_cfg80211_sched_scan_start: Channel_List= %s " %(m.group("Channel_List")),  line_no, time_stamp)
                    if m.group("hidde_networks") is not None:
                        LogMsg(LOG_WARN, " __wlan_hdd_cfg80211_sched_scan_start: hidde_networks= %s " %(m.group("hidde_networks")),  line_no, time_stamp, "green", "bright")
                    if m.group("base_scan") is not None:
                        LogMsg(LOG_WARN, " __wlan_hdd_cfg80211_sched_scan_start: Base scan interval= %s, PNOScanTimerRepeatValue=%s " %(m.group("base_scan"), m.group("PNOScanTimerRepeatValue")),  line_no, time_stamp, "green", "bright")

                #23:07:55.003334  R0: [wificond][7650747983] [23:07:55.001726] wlan: [1151:IL:HDD] __wlan_hdd_cfg80211_sched_scan_stop: 3579: enter(wlan0)
                elif (pattern[1][1] == 10):
                        LogMsg(LOG_WARN, " __wlan_hdd_cfg80211_sched_scan_stop: enter" ,  line_no, time_stamp, "green" )


                #<6>[ 2832.580795] (2)[1985:cds_mc_thread]R0: [cds_mc_thread][54465337197] [20:07:38.422864] wlan: [1985:E :SME] csr_scan_active_list_timeout_handle: 8266: Scan Timeout:Sending abort to Firmware ID 40966 session 0
                elif (pattern[1][1] == 11):
                        LogMsg(LOG_ERR, " scan timeout aborting scan_id 0x%x, Device_mode= %s" %(int(m.group("scan_id")), scan_info["Device_mode"]),  line_no, time_stamp, "red", "bright")


    #10:36:12.391667  R0: [cds_mc_thread][1400763867514] [10:36:12.376748] wlan: [1859: D:SME] _csr_calculate_bss_score: 1871: BSSID:20:6b:e7:83:50:04 rssi=-78 htcaps=1 vht=0 bw=1 channel=1 beamforming=0 ap_load=0 est_air_time_percentage=0 pcl_score 0 Final Score 3520 ap_NSS 3 nss 2 dot11mode 7 is_vht 1
                elif (pattern[1][1] == 12):
                    temp_bssid_hint=1

                #10:36:11.101223  R0: [wificond][1400738502276] [10:36:11.055641] wlan: [1217: D:QDF] cds_is_connection_in_progress: 2918: 0000000000000000(0) Connection is in progress
                elif (pattern[1][1] == 13):
                    scan_started=0

                #10:37:41.430100  R0: [cds_mc_thread][1402472551955] [10:37:41.370729] wlan: [1859: D:PE ] lim_process_abort_scan_ind: 1215: scan_id 42525, scan_requestor_id 0xa000
                elif (pattern[1][1] == 14):
                    LogMsg(LOG_CRIT, " scan aborting drop scan_id =0x%x" %(int(m.group("scan_id"))),  line_no, time_stamp, "red" )
                    scan_started=0
                #####
                ####   connection
                ###    idx starting from 15
                ##
                #11:16:05.239647  R0: [wpa_supplicant][1161066234781] [11:16:05.239053] wlan: [23177:IL:HDD] __wlan_hdd_cfg80211_connect: 13794: enter
                #elif(pattern[1][1] == 15):
                #TBD    
                #11:16:05.241625  R0: [wpa_supplicant][1161066266201] [11:16:05.240689] wlan: [23177:IH:HDD] wlan_hdd_cfg80211_connect_start: 12675: bssid is given by upper layer 70:df:2f:b6:ea:0e
                elif (pattern[1][1] == 16):	
                    if m.group("BSSID") is not None:
                        peer_info.update({"BSSID":m.group("BSSID")})
                    SSID=m.group("SSID")
                    Channel=m.group("Channel")
                    if (SSID is not None ) or (Channel is not None ):
                        peer_info.update({"SSID":SSID, "channel": Channel })
                        #LogMsg(LOG_WARN, "SSID %s channel%s"   %(SSID, Channel), line_no, 0)
                    

                    if m.group("BSSID") is not None:
                        LogMsg(LOG_WARN, "UTC time - %s " %(get_utctimestamp(line)),  line_no, '0')
                        LogMsg(LOG_CRIT, "Connection initiated with BSSID =%s " % peer_info["BSSID"],  line_no, time_stamp,"white", "bright")
                        connection_times.append(time_stamp)


                #10:06:32.445882  R0: [cds_mc_thread][945468863941] [10:06:32.437100] wlan: [1633: D:WMA] TX MGMT - Type 0, SubType 11 seq_num[2122]
                elif (pattern[1][1] == 20):	
                    subType=(m.group("SubType"))
                    if (get_subType(subType) == "De-Auth") or (get_subType(subType) == "Dis-assoc"):
                        LogMsg(LOG_WARN, "DUT initiated disconnection with [%s] frame SN=%s " % (get_subType(subType),m.group("seq_num")), line_no, time_stamp,"red", "bright")
                        set_state("DISCONNECTED_STATE")
                    else:
                        LogMsg(LOG_WARN, "Tx [%s] frame SN= %s " % (get_subType(subType),m.group("seq_num")), line_no, time_stamp,"yellow", "bright")
                        if(get_subType(subType) == "Auth" and ((get_state() =="SCAN_STATE") or  (get_state() =="SCAN_SENT") )):
                            set_state("AUTH_STATE")
                        elif(get_subType(subType) == "AssocReq"and get_state() =="AUTH_STATE"):
                            set_state("ASSOC_STATE")


                #10:06:11.671989  R0: [cds_mc_thread][945070155384] [10:06:11.671029] wlan: [1633: D:PE ] lim_handle80211_frames: 936: RX MGMT - Type 0, SubType 11, seq num[439]
                #('lim_handle80211_frames',[r'lim_handle80211_frames\:\\s(\d+).*\sSubType\s(\d+).*\snum(\[(\d+)\])',21,1,1]),
                elif (pattern[1][1] == 21):	
                    subType=m.group("SubType")
                    if (get_subType(subType) == "De-Auth") or (get_subType(subType) == "Dis-assoc"):
                        LogMsg(LOG_CRIT, "AP initiated disconnection with  [%s] frame SN= %s " % (get_subType(subType),m.group("seq_num")), line_no, time_stamp,"red", "bright")
                    else:
                        LogMsg(LOG_WARN, "Rx  [%s] frame SN= [%s] " % (get_subType(subType),m.group("seq_num")), line_no, time_stamp,"yellow", "bright")


                #11:16:17.798704  R0: [cds_mc_thread][1161306737117] [11:16:17.765215] wlan: [23163:IH:HDD] hdd_sme_roam_callback: 4768: ****eCSR_ROAM_ASSOCIATION_COMPLETION****
                elif (pattern[1][1] == 22)  :	
                    if(m.group("ASSOC_STATUS") == "eCSR_ROAM_ASSOCIATION_COMPLETION"):
                        if connection_times:
                            total_connect_time=(time_stamp-connection_times.pop())/19200
                            if "STATE" in peer_info :
                                if(get_state()=="ASSOC_STATE"):
                                    LogMsg(LOG_CRIT, "***********eCSR_ROAM_ASSOCIATION_COMPLETION(time=%d msec)*********" %(total_connect_time), line_no, time_stamp,"yellow", "bright")
                            connect_cnts.append(1);
                            if (total_connect_time >5000):
                                LogMsg(LOG_CRIT, "***********Longer connection time(%d)*********" % total_connect_time, 0, 0, "red", "bright")
                    elif(m.group("ASSOC_STATUS") == "eCSR_ROAM_DISASSOCIATED"):
                        LogMsg(LOG_WARN, "UTC time - %s " %(get_utctimestamp(line)),  line_no, '0')
                        LogMsg(LOG_CRIT, "***********eCSR_ROAM_DISASSOCIATED*********", line_no, time_stamp,"yellow", "bright")
                        LogMsg(LOG_WARN, "RSSI= %s at disconnection " % (peer_info["disconnect_rssi"]), line_no, time_stamp,"yellow", "bright")
                        if graphical_enable !=0 :
                            if len(peer_info["rate_array"]) !=0:
                                x_1 = range(len(peer_info["rate_array"])) 
                                plt.suptitle("BSSID=%s" %peer_info["BSSID"], size=16)
                                #x=np.arange(0, len(peer_info["rate_array"]), 1)
                                plt.subplot(121)
                                plt.xlabel('Index')
                                min_rssi=smallest_num_in_list(peer_info["RSSI_array"])
                                plt.ylim(ymax=min_rssi)  # this line
                                plt.ylabel('RSSI')
                                plt.bar(x_1 ,peer_info["RSSI_array"])
                                plt.subplot(122)
                                plt.xlabel('Index')
                                plt.ylabel('Rate')
                                plt.ylim(ymax=largest_num_in_list(peer_info["rate_array"]))  # this line
                                plt.bar(x_1 ,peer_info["rate_array"])
                                plt.show()

                        ##Clear peer_info dictionary
                        peer_info = {key: [] for key in peer_info}


                #19:36:30.984881  R0: [cds_mc_thread][10164517325] [19:36:30.971971] wlan: [5865: D:WMI] send_peer_assoc_cmd_tlv: vdev_id 0 associd 1 peer_flags 201002 rate_caps 8 peer_caps 401 listen_intval 1 ht_caps c max_mpdu 65535 nss 1 phymode 5 peer_mpdu_density 0 cmd->peer_vht_caps 0
                elif (pattern[1][1] == 23 and pattern[1][3] == 1):	
                    peer_info.update({"vdev_id":m.group("vdev_id"), "associd":m.group("associd"), "peer_flags":m.group("peer_flags")})
                    peer_info.update({"rate_caps":m.group("rate_caps"), "peer_caps":m.group("peer_caps"), "listen_intval":m.group("listen_intval")})
                    peer_info.update({"ht_caps":m.group("ht_caps"), "max_mpdu":m.group("max_mpdu"), "nss":m.group("nss")})
                    peer_info.update({"phymode":m.group("phymode"), "peer_mpdu_density":m.group("peer_mpdu_density"), "peer_vht_caps":m.group("peer_vht_caps")})
                    LogMsg(LOG_WARN, "Peer info: BSSID = %s, SSID = %s, channel = %s, vdev_id = %s , listen_intval = %s, ht_caps = %s, phymode = %s" % (peer_info["BSSID"], peer_info["SSID"], peer_info["channel"], peer_info["vdev_id"],  peer_info["listen_intval"], peer_info["ht_caps"], peer_info["phymode"]),  line_no, time_stamp,"green", "bright")

                #17:29:31.449191  R0: [cds_mc_thread][1307968374678] [17:29:31.442454] wlan: [2223: D:PE ] lim_add_sta_self: 2851: sessionid: 0  Assoc ID: 2 listenInterval = 1 shortPreambleSupported: 1
                elif (pattern[1][1] == 23 and pattern[1][3] == 2):	
                        LogMsg(LOG_WARN, "associd = %s" % ((m.group("aid"))),  line_no, time_stamp,"green", "bright")

                #19:37:12.376803  R0: [cds_mc_thread][10959425206] [19:37:12.373423] wlan: [5865: D:PE ] lim_process_switch_channel_join_req: 3006: Sessionid: 0 Send Probe req on channel 6 ssid:CMW-AP BSSID: 00:01:02:03:04:05
                elif (pattern[1][1] == 24 and pattern[1][3] == 1):	
                    peer_info["BSSID"]=m.group("BSSID")
                    peer_info["SSID"]=m.group("ssid")
                    peer_info["channel"]=m.group("channel")
                    LogMsg(LOG_WARN, "Probe transmitted in Ch # %s; SSID = %s, BSSID = %s " % (int(m.group("channel")), m.group("ssid"), m.group("BSSID")),  line_no, time_stamp,"green", )
                    set_state("SCAN_STATE")
                elif (pattern[1][1] == 24 and pattern[1][3] == 2):	
                    if(get_state()=="SCAN_STATE"):
                        LogMsg(LOG_WARN, "Probe Req SN# %s" % (int(m.group("SN"))),  line_no, time_stamp,"green", )
                        set_state("SCAN_SENT")


                #19:33:42.923495  R0: [cds_mc_thread][6937927990] [19:33:42.920443] wlan: [5865: D:WMA] wma_process_mgmt_tx_completion: status: 2 wmi_desc_id: 1
                elif (pattern[1][1] == 25):	
                    '''
                    #if "STATE" in peer_info:
                    if(get_state()=="SCAN_STATE"):
                        if(int(m.group("tx_status")) !=0):
                            LogMsg(LOG_ERR, "Probe Tx status %d " % int(m.group("tx_status")),  line_no, time_stamp,"red", "bright")
                        elif(int(m.group("tx_status")) ==0):
                            LogMsg(LOG_INFO, "Probe Tx status %d " % int(m.group("tx_status")),  line_no, time_stamp,"white", "bright")
                    elif(get_state()=="AUTH_STATE"):
                        if(int(m.group("tx_status")) !=0):
                            LogMsg(LOG_ERR, "Auth Tx status %d " % int(m.group("tx_status")),  line_no, time_stamp,"red", "bright")
                            set_state("DISCONNECTED_STATE")
                        elif(int(m.group("tx_status")) ==0):
                            LogMsg(LOG_INFO, "Auth Tx status %d " % int(m.group("tx_status")),  line_no, time_stamp,"white", "bright")
                    elif(get_state()=="ASSOC_STATE"):
                        if(int(m.group("tx_status")) !=0):
                            LogMsg(LOG_ERR, "Assoc Tx status %d " % int(m.group("tx_status")),  line_no, time_stamp,"red", "bright")
                            set_state("DISCONNECTED_STATE")
                        elif(int(m.group("tx_status")) ==0):
                            LogMsg(LOG_INFO, "Assoc Tx status %d " % int(m.group("tx_status")),  line_no, time_stamp,"white", "bright")
                    '''
                    if(int(m.group("tx_status")) !=0):
                        LogMsg(LOG_ERR, "Tx status %d " % int(m.group("tx_status")),  line_no, time_stamp,"red", "bright")

                #11:14:03.548545  R0: [cds_mc_thread][66713152360] [11:14:03.514125] wlan: [1805: D:HDD] hdd_association_completion_handler: 2764: sending connect indication to nl80211:for bssid 20:6b:e7:83:50:04 result:2 and Status:7
                elif(pattern[1][1] == 26):
                    if (m.group("sucess_status") is not None): 
                        LogMsg(LOG_WARN, "Connection status %s " % (get_connection_status(int(m.group("sucess_status")))),  line_no, time_stamp,"green", "bright")
                    if (m.group("fail_status") is not None): 
                        LogMsg(LOG_CRIT, "Connection status %s in %s" % (get_connection_status(int(m.group("fail_status"))),  get_state()),  line_no, time_stamp,"red", "bright")


                #11:16:00.490343  R0: [cds_mc_thread][1160974885032] [11:16:00.481253] wlan: [18734:IH:HDD] hdd_lost_link_info_cb: 1186: rssi on disconnect -71
                elif (pattern[1][1] == 27):	
                        peer_info["disconnect_rssi"]=m.group("disconnect_rssi")


                #15:06:44.505305  R0: [cds_mc_thread][46723330859] [15:06:44.487421] wlan: [2276: D:QDF] cds_dump_current_concurrency: 3282: SAP+STA DBS
                elif (pattern[1][1] == 28):	
                    DUT_info["concurrency"] = m.group("concurrency")
                    LogMsg(LOG_CRIT, "cds_dump_current_concurrency %s " % (DUT_info["concurrency"] ),  line_no, time_stamp,"green", "bright")


                #('__wlan_hdd_cfg80211_get_station',[r'.+\sRSSI\s(?P<RSSI>.*).*\srate\s(?P<rate>\d+)',29,1,1]),
                elif (pattern[1][1] == 29):	
                    if(get_state()=="ASSOC_STATE"):
                        peer_info["RSSI_array"].append(int(m.group("RSSI")))
                        peer_info["rate_array"].append(int(m.group("rate"))/10)
                        LogMsg(LOG_VERB, "BSSId= %s, RSSI= %s, Rate= %s  " % (peer_info["BSSID"], m.group("RSSI"), m.group("rate")),  line_no, time_stamp)
                
                #15:06:52.280606  R0: [cds_mc_thread][46872824952] [15:06:52.273572] wlan: [2276: D:PE ] lim_get_min_session_txrate: 7466: supported min_rate: 2(2)
                elif (pattern[1][1] == 30):	
                    LogMsg(LOG_WARN, "Min supported rate= %s  " % (int(m.group("min_rate"))/2),  line_no, time_stamp)


                #15:06:24.833558  R0: [cds_mc_thread][46345827031] [15:06:24.825763] wlan: [2276:E :PE ] lim_process_auth_frame: 1137: auth frame, seq num: 256 is already processed, drop it
                elif (pattern[1][1] == 31):	
                    LogMsg(LOG_WARN, "Auth frame [%s] already processed, drop it  " % m.group("SN"),  line_no, time_stamp, "red", "bright")

                #19:35:07.578111  R0: [cds_mc_thread][17008394409] [19:35:07.540427] wlan: [1985:I :HDD] hdd_hostapd_sap_event_cb: 1973:  associated d4:1a:3f:00:26:93
                elif (pattern[1][1] == 32):	
                    LogMsg(LOG_WARN, "UTC time - %s " %(get_utctimestamp(line)),  line_no, '0')
                    LogMsg(LOG_CRIT, "Associated with %s  " % m.group("client_mac"),  line_no, time_stamp, "green", "bright")

                #19:40:26.102378  R0: [cds_mc_thread][23124510756] [19:40:26.088153] wlan: [1985:W :PE ] lim_reject_association: 898: received Re/Assoc req when max associated STAs reached from
                elif (pattern[1][1] == 33):	
                    LogMsg(LOG_CRIT, "MAX STA count reached issue deny connection" ,  line_no, time_stamp, "red", "bright")
                    
                #11:03:05.067940  R0: [wpa_supplicant][4763620533] [11:03:04.428898] wlan: [2599: D:SME] csr_roam_print_candidate_aps: 8198: BSSID 50:fa:84:31:c5:3c score is 3054
                elif (pattern[1][1] == 34):	
                    LogMsg(LOG_INFO, "BSSID= %s, score = %d" %(m.group("BSSID"), int(m.group("score"))),  line_no, time_stamp, "MAGENTA", "bright")

                #17:07:43.230495  R0: [cds_mc_thread][424950728082] [17:07:43.227895] wlan: [1575: D:PE ] sch_beacon_edca_process: 1057: AC[0]:  AIFSN: 3, ACM 0, CWmin 4, CWmax 10, TxOp 0
                elif ((pattern[1][1] == 35) and (pattern[1][3] == 1)):	
                    LogMsg(LOG_INFO, "Process EDCA from probe rsp/beacon: AC%s" %(m.group("edca_params")),  line_no, time_stamp, "white", "bright")


                #17:07:43.230602  R0: [cds_mc_thread][424950730675] [17:07:43.228030] wlan: [1575: D:PE ] lim_send_edca_params: 355: AC[0]:  AIFSN 3, ACM 0, CWmin 4, CWmax 10, TxOp 0 
                elif ((pattern[1][1] == 35) and (pattern[1][3] == 2)):	
                    LogMsg(LOG_INFO, "update EDCA: AC%s" %(m.group("edca_params")),  line_no, time_stamp, "MAGENTA", "bright")

                #14:52:42.053144  R0: [cds_mc_thread][395699370515] [14:52:42.049010] wlan: [2307:E :PE ] lim_process_auth_frame_type1: 335: STA is already connected but received auth frame Send the Deauth and lim Delete Station Context staId: 1 associd: 4
                elif (pattern[1][1] == 36):	
                    LogMsg(LOG_ERR, "STA is already connected but received auth frame Send the Deauth" ,  line_no, time_stamp, "MAGENTA", "bright")

                #14:33:44.070809  R0: [cds_mc_thread][373838133557] [14:33:44.054948] wlan: [2307: D:PE ] lim_process_deauth_frame: 165: Received Deauth frame for Addr: e0:c1:43:27:b8:00(mlm state = eLIM_MLM_LINK_ESTABLISHED_STATE, sme state = 11 systemrole = 3 RSSI = -58) with reason code 6 [eSIR_MAC_CLASS2_FRAME_FROM_NON_AUTH_STA_REASON] from 74:ea:cb:35:9d:71
                elif ((pattern[1][1] == 37) and (pattern[1][3] == 1)):	
                    LogMsg(LOG_CRIT, "Deauth reason_code %s from %s" %(m.group("reason_code"),m.group("BSSID")),  line_no, time_stamp, "red", "bright")

                #17:42:18.337909 R0: [cds_mc_thread][110033097669] [17:42:18.333080] wlan: [1939: D:PE ] lim_process_disassoc_frame: 162: Received Disassoc frame for Addr: 8e:fd:f0:89:b3:44(mlm state=eLIM_MLM_BSS_STARTED_STATE, sme state=18 RSSI=-33),with reason code 8 [eSIR_MAC_DISASSOC_LEAVING_BSS_REASON] from 40:83:de:c3:6c:e5
                elif ((pattern[1][1] == 37) and (pattern[1][3] == 2)):	
                    LogMsg(LOG_CRIT, "Disassoc reason_code %s from %s" %(m.group("reason_code"),m.group("BSSID")),  line_no, time_stamp, "red", "bright")

                ####
                ##
                #
                #11:16:00.440594  R0: [wpa_supplicant][1160974089489] [11:16:00.439818] wlan: [18741:IL:HDD] __wlan_hdd_cfg80211_disconnect: 14112: enter
                elif (pattern[1][1] == 41):	
                    LogMsg(LOG_CRIT, "User initiated disconnect ", line_no, time_stamp,"red", "bright")


                #19:36:48.543804  R0: [cds_mc_thread][10501431053] [19:36:48.519561] wlan: [5865: D:WMA] wma_peer_sta_kickout_event_handler: Enter
                elif (pattern[1][1] == 42):	
                    LogMsg(LOG_CRIT, "wma_peer_sta_kickout_event_handler", line_no, time_stamp,"red", "bright")


                #10:48:04.700853  R0: [cds_mc_thread][1731670570387] [10:48:04.695857] wlan: [1922: D:PE ] lim_handle_heart_beat_failure: 501: HB missed from AP. Sending Probe Req
                elif (pattern[1][1] == 43):	
                    LogMsg(LOG_CRIT, "HB missed from AP, Sending probe req", line_no, time_stamp,"red", "bright")

                #10:48:04.800764  R0: [cds_mc_thread][1731671778945] [10:48:04.758803] wlan: [1922: D:PE ] lim_handle_heart_beat_failure_timeout: 5575: SME: 11 MLME: 16 HB-Count: 0
                elif (pattern[1][1] == 44):	
                    LogMsg(LOG_CRIT, "NO probe rsp, teardown connection", line_no, time_stamp,"red", "bright")

                # 15:09:43.829634  R0: [cds_mc_thread][50166694222] [15:09:43.829263] wlan: [2276:E :QDF] cds_flush_logs: Triggering bug report: type:1, indicator=2 reason_code=14
                elif (pattern[1][1] == 45):	
                    LogMsg(LOG_CRIT, "Triggering bug report reason_code= [%s]" %(get_reasoncode(int(m.group("reason_code")))), line_no, time_stamp,"red", "bright")

                ###
                ##DBS info
                #

                elif(pattern[1][1] == 50):
                    DUT_info.update({"DBS":m.group("DBS")})
                #07:37:05.275853  R0: [soft_irq][852668327749] [07:37:05.223997] wlan: [0:F :WMA] Non-WLAN triggered wakeup: UNSPECIFIED (-1)
                elif(pattern[1][1] == 61):
                    LogMsg(LOG_INFO, "%s" % (m.group(1)),line_no, time_stamp,"green", "bright")

                #07:25:28.990327  R0: [soft_irq][839299812618] [07:25:28.947167] wlan: [0:F :WMA] uc 414 bc 0 v4_mc 1893 v6_mc 0 ra 0 ns 0 na 0 pno_match 0 pno_complete 0 gscan 0 low_rssi 0 rssi_breach 0 icmp 0 icmpv6 0 oem 0
                elif(pattern[1][1] == 62):
                    LogMsg(LOG_INFO, "%s" % (m.group(1)),line_no, time_stamp,"white", "bright")


                #23:02:01.341761  R0: [kworker/u16:16][682329081] [03:01:16.725003] wlan: [1104: D:HDD] hdd_cfg_print: 5829: Name = [RTSThreshold] Value = 1048576
                elif(pattern[1][1] == 81):
                    LogMsg(LOG_WARN, "%s" % (m.group("config")), 0,time_stamp, "white", "bright")
                    
                #23:02:01.384872  R0: [android.hardwar][750006043] [21:57:36.669783] wlan: [749: D:SME] csr_init_operating_classes: 20396: Current Country = US
                elif(pattern[1][1] == 91):
                    LogMsg(LOG_ERR, "Country Code: %s" % (m.group("CC")), line_no,time_stamp, "green", "bright")
                    #DUT_info.append({"CC":m.group("CC")})
                    DUT_info["CC"].append(m.group("CC"))

                #23:08:25.722196  R0: [cds_mc_thread][8240539042] [23:08:25.720009] wlan: [1584: D:WMI] Send WMI command:WMI_VDEV_SET_PARAM_CMDID command_id:20488 htc_tag:0
                elif(pattern[1][1] == 92):
                    LogMsg(LOG_VERB, "WMI CMD: %s - 0x%x" % (m.group("CMD"), int(m.group("id"))), line_no,time_stamp, "CYAN" )


                #12:23:00.991381  R0: [cds_mc_thread][3554662988] [12:23:00.960645] wlan: [3139: D:SME] csr_process_roam_sync_callback: 21111: LFR3: reason: 3
                elif(pattern[1][1] == 101):
                    LogMsg(LOG_WARN, "csr_process_roam_sync_callback [%s]" % (get_roam_op_reason(int(m.group("reason")))), line_no,time_stamp, "MAGENTA", "bright" )
                #12:23:01.019780  R0: [cds_mc_thread][3555644653] [12:23:01.011773] wlan: [3139: D:SME] LFR3:csr_neighbor_roam_indicate_connect
                elif(pattern[1][1] == 102):
                    LogMsg(LOG_WARN, "hdd_send_association_event in roaming BSSID =%s" %(candidate_mac.pop()), line_no,time_stamp, "green", "bright" )
                #12:23:25.582966  R0: [cds_mc_thread][4026733360] [12:23:25.547643] wlan: [3139: D:WMA] LFR3:wma_add_bss_sta_mode: bssid 70:f3:5a:48:9a:0e staIdx 1
                elif(pattern[1][1] == 103):
                    candidate_mac.append(m.group("candidate_mac"))

                #17:37:03.031928  R0: [kworker/3:2][110120957111] [17:37:03.029743] wlan: [8847: D:WMA] data_stall_type: 3 vdev_id_bitmap: 1 reason_code1: 0 reason_code2: 7 recovery_type: 0 
                elif(pattern[1][1] == 111):
                    LogMsg(LOG_WARN, "Data Stall event: type = [ %s ], reason_code1 = %s, reason_code2 = %s recovery_type = [ %s ]" %(get_data_stall_type(int(m.group("data_stall_type"))), m.group("reason_code1"), m.group("reason_code2"), get_recovery_type(int(m.group("recovery_type")))), line_no,time_stamp, "yellow", "bright" )


                '''
                if(pattern[1][1] == 51):
                        field_index = 0
                        if (wmi_ready == 0):
                                HW_info.append(m.group(field_index_incr()))
                                HW_details_idx +=1
                if(pattern[1][1] == 42):
                        wmi_ready = 1
                '''

        line_no += 1

#####
###  Format:
##  python parser.py <log_level> <log_file>
#   eg: python parser.py -vv  host_driver_logs_current_1.txt
Newpath = sys.argv[1]
'''
print(type(sys.argv[len(sys.argv)-1]))
print(sys.argv[len(sys.argv)-2])
if(len(sys.argv) > 2):
    Newpath = sys.argv[len(sys.argv)-1]
    if(sys.argv[len(sys.argv)-2] == "-G"):
        graphical_enable=1
    log_mask=get_logmask(sys.argv[len(sys.argv)-3])
'''
#if( "-v" in sys.argv[1]) :
if(sys.argv[1].startswith("-v")) :
    log_mask=get_logmask(sys.argv[1])
    if( "-G" in sys.argv[2]) :
        graphical_enable=1
        Newpath = sys.argv[3]
    else:
        Newpath = sys.argv[2]
#elif( "-G" in sys.argv[1]) :
elif( sys.argv[1].startswith("-G")) :
        graphical_enable=1
        Newpath = sys.argv[2]

    

initialize_dictionaries()
#peer_info["RSSI_array"].append(m.group("RSSI"))
ProcessResults(Newpath)
print("###########################################")
LogMsg(LOG_WARN, "MAC: %s"% DUT_info["MAC"], 0,'0', "green", "bright")
LogMsg(LOG_WARN, "DBS Enable: %s"% (DUT_info["DBS"]), 0,'0', "green", "bright")
if(DUT_info["CC"]):
    LogMsg(LOG_WARN, "Country code: %s"% (set(DUT_info["CC"])), 0,'0', "green", "bright")
LogMsg(LOG_WARN, "Dwell times Min: %s, Max: %s"% ( DUT_info["minChnTime"],DUT_info["maxChnTime"]), 0,'0', "green", "bright")
LogMsg(LOG_WARN, "Total #of scans %d" % (sum(scan_req_count)), 0,'0', )
LogMsg(LOG_WARN, "Total #of connections %d" % (sum(connect_cnts)), 0,'0', )
print("############################################")
'''
print (peer_info)
print (scan_info)
print (DUT_info)
'''
#print (scan_history)
scan_dictionary = dict(zip(scan_history["scan_id"], scan_history["raw_BSS"]))
#print(scan_dictionary)

if graphical_enable !=0 :
    if len(scan_history["scan_id"]) !=0 :
        plt.suptitle("DUT=%s" %DUT_info["MAC"], size=16)
        plt.xlabel('scan_id')
        plt.ylabel('#of BSS')
        min_BSS=smallest_num_in_list(scan_history["raw_BSS"])
        max_BSS=largest_num_in_list(scan_history["raw_BSS"])
        plt.ylim(ymax=max_BSS)  # this line
        plt.bar(scan_history["scan_id"] ,scan_history["raw_BSS"])
        plt.show()
