import json
import requests
import os

def check_ip(url):
    try:
        res = requests.get(url)
        return False
    except:
        return True

abs_path = os.path.abspath(__file__)
exec_path = abs_path.replace('/batch/health_check.py', '')
peers_path = "{}/config/peers.dat".format(exec_path)
peers_tmp_path = "{}/config/peers_tmp.dat".format(exec_path)
with open(peers_path) as reader, open(peers_tmp_path, 'w') as writer:
    for line in reader:
        if line != '\n':
            json_open = json.loads(line)
            ip = json_open['ip']
            url = f"http://{ip}:3000/health"
            if json_open['protocol'] == 'ipv6': 
                url = f"http://[{ip}]:3000/health"
            if check_ip(url):
                line = line.replace("\"ACTIVE\"", "\"INACTIVE\"")
                writer.write(line)
            else:
                line = line.replace("\"INACTIVE\"", "\"ACTIVE\"")
                writer.write(line)

with open(peers_tmp_path) as reader:
    content = reader.read()
with open(peers_path, 'w') as writer:
    writer.write(content)