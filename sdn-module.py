import json
import sys
import requests as re
import icecream as ic
import pandas as pd

controller_url =  'http://192.168.122.126:8181/restconf'
node_list = []
flow_tables = []

def main():
    print("SDN Module")
    get_all_nodes()
    print(node_list)
    get_all_flows()

def get_all_nodes():
    node_url = controller_url + '/operational/opendaylight-inventory:nodes'
    print(node_url)
    resp = re.get(node_url, auth=('admin', 'admin'))
    print(f"Status code: {resp.status_code}")
    resp_dict = resp.json()
    nodes_dict = resp_dict['nodes']#['node']
    #print(list(nodes_dict.id()))
    #print(nodes_dict)
    for i in nodes_dict['node']:
        node_list.append(i['id'])

def get_all_flows():
    for i in node_list:
        node_flows = controller_url + '/operational/opendaylight-inventory:nodes/node/' + i
        print(node_flows)
        resp = re.get(node_flows, auth=('admin', 'admin'))
        resp_dict = resp.json()
        print('Get All Flows')
   
        for i in resp_dict['node']:
            for j in i['flow-node-inventory:table']:
                if j['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows'] >= 1:
                    flow_tables.append(j)
        print(pd.DataFrame(flow_tables))

def add_flow(table, flow_id):
    

#def delete_flow();

if __name__ == "__main__":
    main()