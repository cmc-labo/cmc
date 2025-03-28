import json
import requests
import os

peers_list = []
url_list = []

abs_path = os.path.abspath(__file__)
exec_path = abs_path.replace('/batch/broadcast_peers.py', '')
peers_path = "{}/config/peers.dat".format(exec_path)
with open(peers_path) as f:
    for line in f:
        json_open = json.loads(line)
        peers_list.append(json_open)
        if json_open['status'] == 'ACTIVE':
            ip = json_open['ip']
            if json_open['protocol'] == 'ipv6': 
                url = f"http://[{ip}]:3000/fetch_peers"
            else:
                url = f"http://{ip}:3000/fetch_peers"
            url_list.append(url)

peers_data = json.dumps(peers_list)
for url in url_list:
    response = requests.post(
        url,
        data=peers_data,
        headers={'Content-type': 'application/json'}
    )
    print(response.status_code)