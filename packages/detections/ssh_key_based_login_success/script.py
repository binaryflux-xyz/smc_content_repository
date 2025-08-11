def window():
    return None

def groupby():
    return None

def algorithm(event):
    if event['action'] == 'sshd' and 'Accepted publickey for' in event['event_message']:
      return 0.50
    return 0.0

def context(event_data):
    return "A successful SSH login using a public key was detected from IP address " + event_data['user_ip'] + \
           " on host " + event_data['host'] + ". Public key-based authentication is commonly used for secure, automated access."


def criticality():
    return 'MEDIUM'

def tactic():
    return 'Initial Access (TA0001)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['host', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event['user_ip'], 'type': 'ipaddress'}