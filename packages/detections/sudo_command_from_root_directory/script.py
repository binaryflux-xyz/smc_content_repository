def window():
    return '10m'

def groupby():
    return ['user_ip']

def algorithm(event):
    if event['action'] == 'sudo' and 'root : PWD=/root' in event['event_message']:
        if stats.count('user_ip') > 3:
            return 0.50
    return 0.0

def context(event_data):
    return "Root Directory was accessed using the sudo permissions for the user_ip " + event_data['user_ip']

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Obfuscated Files or Information (T1027)'

def artifacts():
    return stats.collect(['hostname', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event['user_ip'], 'type': 'ipaddress'}