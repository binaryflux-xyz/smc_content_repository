def window():
    return None
def groupby():
    return None
def algorithm(event):
    if event.get('event_id') == 4688:
        if 'powershell.exe' in event.get('process_name', ''):
            suspicious_keywords = ['DownloadString', 'IEX', 'Invoke-Expression', 'bypass']
            command_line = event.get('command_line', '')
            for keyword in suspicious_keywords:
                if keyword in command_line:
                    return 0.75
    return 0.0
def context(event_data):
    return "Suspicious PowerShell command executed: " + event_data['command_line']
def criticality():
    return 'HIGH'
def tactic():
    return 'Execution (TA0002)'
def technique():
    return 'PowerShell (T1059/001)'
def artifacts():
    return stats.collect(['process_name', 'command_line'])
def entity(event):
    return {'derived': False, 'value': event['process_name'], 'type': 'process'}