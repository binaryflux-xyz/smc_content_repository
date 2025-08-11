def window():
    return '10m'
def groupby():
    return ['source_ip']
def algorithm(event):
    if event['event_id'] == 4624 and event['logon_type'] == 10:
        if stats.count('source_ip') > 5:
            return 0.75
    return 0.0
def context(event_data):
    return "More than five RDP (Logon Type 10) logins from " + event_data['source_ip'] + " within 10 minutes."
def criticality():
    return 'HIGH'
def tactic():
    return 'Lateral Movement (TA0008)'
def technique():
    return 'Remote Services (T1021/001)'
def artifacts():
    return stats.collect(['source_ip', 'event_id', 'logon_type'])
def entity(event):
    return {'derived': False, 'value': event['source_ip'], 'type': 'ipaddress'}