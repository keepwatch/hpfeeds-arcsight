#!/usr/bin/python

def format(message):
    tmpmsg = dict(message)
    mappingDict = {"src_ip": "src", "src_port": "spt", "dst_ip": "dst", "dst_port": "dpt", "transport": "proto", "direction": "deviceDirection", "vendor_product": "cs1", "ids_type": "cs2", "app": "ds3"}
    
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
    outmsg = u"CEF:0|ThreatStream|MHN|1.0|{}|{}|{}|".format(sig, name, sev)

    # Replace transport field with protocol value if blank
    if not tmpmsg['transport']:
        tmpmsg['transport'] = tmpmsg['protocol']
        
    # Iterate through remaining properties and append to outmsg
    for name, value in tmpmsg.items():
        if value and name in mappingDict:
            if name == 'direction':
                value = 0 if value == 'inbound' else 1
            outmsg += "{}={}".format(mappingDict[name], value)
            if mappingDict[name][:1] == "cs":
                outmsg += "{}Label={}".format(mappingDict[name], name)

    return outmsg
