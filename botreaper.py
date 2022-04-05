import os 
import pyshark
import time 
import subprocess
import glob
import boto3
import json


hosts = {}
config = {}

def read_config(config_filename="config.txt"):
    with open(config_filename) as f:
        for line in f:
            (key, val) = line.split("=")
            config[str(key)] = val

def write_json():    
    with open(config['JSON_FILENAME'], 'w', encoding='utf-8') as f:    
        json.dump(hosts, f, ensure_ascii=False, default=lambda x: list(x) if isinstance(x, set) else x)    
        
def upload_to_aws():
    session = boto3.Session(aws_access_key_id=config['AWS_ACCESS_KEY_ID'], aws_secret_access_key=config['AWS_ACCESS_KEY_SECRET'])
    s3 = session.resource('s3')
    bucket = s3.Bucket(name=config['AWS_BUCKET_NAME'])
    bucket.upload_file(config['JSON_FILENAME'], Key=config['AGENT_UPLOAD_FILENAME'])        

def monitor_traffic():
    # Eliminate processes that can interfere with monitor mode
    os.system('airmon-ng check kill')

    # Start monitor mode on interface specified in config
    os.system('airmon-ng start ' + config['WLAN_ADAPTER_NAME'])
    dump = subprocess.Popen(["airodump-ng", wirelessadapter, "-d", gateway_address, "-c", channel, "-w", config['SNIFF_FILENAME'], "-o", "pcap"])

    # Wait for all devices on network to be identified
    time.sleep(int(config['DEVICE_IDENTIFICATION_TIME_SECONDS'])) # wait for all devices on network to be identified
    deauth = subprocess.Popen(["aireplay-ng", "-0", "10", "-a", config['GATEWAY_ADDRESS'], config['WLAN_ADAPTER_NAME']])

    # Sniff for duration set in config
    time.sleep(int(config['SNIFF_TIME_SECONDS']))

    dump.kill()
    deauth.kill()
    print("Finished sniffing")


def parse_traffic():
    mostrecentfile = max(glob.glob(Filename + "*"), key=os.path.getctime)
    capture = pyshark.FileCapture(config['CAPTURE_FILE_PATH'] + mostrecentfile, decryption_key=config['WIFI_PASSWORD'], encryption_type='wpa-pwd')
    capture.set_debug()

    try:
        for packet in capture:
            pkt_source = {}
            is_valid_packet = False
            try:
            # get timestamp
                localtime = time.asctime(time.localtime(time.time()))
             
            # get packet content
                protocol = packet.transport_layer   # protocol type
                src_ip = packet.ip.src            # source address
                src_port = packet[protocol].srcport   # source port
                dst_ip = packet.ip.dst            # destination address
                dst_port = packet[protocol].dstport   # destination port
                src_eth = packet.wlan.sa
                dst_eth = packet.wlan.da
                is_valid_packet = True
            except Exception as e:
                pass

            # ignore packets other than TCP, UDP and IPv4
            if is_valid_packet:

             # output packet info to terminal
                print ("%s IP %s:%s <-> %s:%s (%s) | %s -> %s" % (localtime, src_ip, src_port, dst_ip, dst_port, protocol, src_eth, dst_eth))

            # If new ethernet source, create new record
               if src_eth not in hosts:
                    pkt_source = {'sources': {}, 'dests': {}}
                else:
                    pkt_source = hosts[src_eth]

            # Record source IP
                if src_ip not in pkt_source['sources']:
                    pkt_source['sources'][src_ip] = {'ports': set()}

            # Record desination IP
                if dst_ip not in pkt_source['dests']:
                    pkt_source['dests'][dst_ip] = { 'ports': set()}
                    
            # Record port info
                if src_port not in pkt_source['sources'][src_ip]['ports']:
                    pkt_source['sources'][src_ip]['ports'].add(src_port)
                if dst_port not in pkt_source['dests'][dst_ip]['ports']:
                    pkt_source['dests'][dst_ip]['ports'].add(dst_port)

            # Update hosts dictionary
                hosts.update({src_eth: pkt_source})
                is_valid_packet= False

    except Exception as e:
        print(e) 
        
def print_to_terminal():
    print('**************** RESULTS *************')
    print(hosts)
    for host in hosts.keys():
        print('Host:\t{}'.format(host))
        print('Source IPs (ports):')
        for src in hosts[host]['sources']:
            srcinfo = str(src)
            if 'ports' in hosts[host]['sources'][src]:
                srcinfo += '\t' + str(hosts[host]['sources'][src]['ports'])
            print('\t{}'.format(srcinfo))
        print('Destination IPs (ports):')
        for dest in hosts[host]['dests']:
            destinfo = str(dest)
            if 'ports' in hosts[host]['dests'][dest]:
                destinfo += '\t' + str(hosts[host]['dests'][dest]['ports'])
            print('\t{}'.format(destinfo))
        print('\n')


def main():
    read_config()
    monitor_traffic()
    parse_traffic()
    print_to_terminal()
    write_json()
    upload_to_aws()
if __name__ == "__main__":
    main()  
