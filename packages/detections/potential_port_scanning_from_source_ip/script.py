def window():
    return '2m'
def groupby():
    return ['host']
def algorithm(event):
    device = event.get('host')
    if event.get('event_id') in [5152, 5157]:
        stats.count(device)
        if stats.getcount(device) >= 20:
            return 0.50
    return 0.0
def context(event_data):
    return "Possible port scanning activity detected from " + event_data['host']
def criticality():
    return 'MEDIUM'
def tactic():
    return 'Reconnaissance (TA0043)'
def technique():
    return 'Active Scanning (T1595)'
def artifacts():
    return stats.collect(['host', 'event_id'])
def entity(event):
    return {'derived': False, 'value': event['host'], 'type': 'devicename'}