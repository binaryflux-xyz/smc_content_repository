def window():
    return None

def groupby():
    return None


def algorithm(event):
    if event['action'] == 'bash' and '/dev/tcp/' in event['event_message']:
        return 1.0  # High confidence for reverse shell
    if event['action'] == 'nc' and ' -e ' in event['event_message']:
        return 1.0
    return 0.0

def context(event_data):
    return "Potential reverse shell spawned on host " + str(event_data['host']) + " with source IP " + str(event_data['user_ip'])

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Command and Control (TA0011)'

def technique():
    return 'Application Layer Protocol (T1071)'
  
def artifacts():
    return stats.collect(['host', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event['user_ip'], 'type': 'ipaddress'}