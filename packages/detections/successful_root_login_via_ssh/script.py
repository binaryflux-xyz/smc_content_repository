def window():
    return '1d'

def groupby():
    return ['user_ip']

def algorithm(event):
    if event['action'] == 'sshd' and 'Accepted password for root' in event['event_message']:
        if stats.getcount(event.get('user_ip')) == 4:
            return 0.75
        else:
          stats.count(event.get('user_ip'))     
    return 0.0


def context(event_data):
    return "A successful SSH login to the root account was detected from IP address " + event_data['user_ip'] + \
           " on host " + event_data['host'] + ". Such activity is considered highly sensitive as direct root access " + \
           "can allow full control over the system. It is recommended to review whether this access was authorized."


def criticality():
    return 'HIGH'

def tactic():
    return 'Initial Access (TA0001)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['host', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event['user_ip'], 'type': 'ipaddress'}