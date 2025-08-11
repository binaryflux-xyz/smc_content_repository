def window():
    return None

def groupby():
    return None

def algorithm(event):
    if event['action'] == 'su' and 'Successful su for root' in event['event_message']:
      return 0.75
    return 0.0

def context(event_data):
    return "A user successfully switched to root using the 'su' command from host " + event_data['hostname'] + " with source IP " + event_data['user_ip']

def criticality():
    return 'HIGH'

def tactic():
    return 'Privilege Escalation (TA0004)'

def technique():
    return 'Abuse Elevation Control Mechanism (T1548)'

def artifacts():
    return stats.collect(['hostname', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event['user_ip'], 'type': 'ipaddress'}