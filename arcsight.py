#!/usr/bin/python

def format(message):
    tmpmsg = dict(message)
    mappingDict = {"src_ip": "src", "src_port": "spt", "dst_ip": "dst", "dst_port": "dpt", "proto": "transport", "direction": "deviceDirection", "vendor_product": "cs1", "ids_type": "cs2", "app": "ds3"}
    
    # Set required variables 
    name = tmpmsg['type']
    if tmpmsg['signature']:
        sig = tmpmsg['signature']
    else:
        sig = name

    sevmap = {"high": "8", "medium": "5", "low": "3"}
    try:
        sev = sevmap[tmpmsg['severity']]
    except:
        sev = 1

    # Set dynamic variables
    outmsg = "CEF:0|ThreatStream|MHN|1.0|{}|{}|{}|".format(sig, name, sev)

    if not tmpmsg['transport']:
        tmpmsg['transport'] = tmpmsg['protocol']

    for name, value in tmpmsg.items():
        if value and name in mappingDict:
            outmsg += "{}={}".format(mappingDict[name], value)
            if mappingDict[name][:1] == "cs":
                outmsg += "{}Label={}".format(mappingDict[name], name)

    return outmsg
