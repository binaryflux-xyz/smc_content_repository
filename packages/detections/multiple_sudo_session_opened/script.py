def window():
    return '1d'

def groupby():
    return ['user_ip']

def algorithm(event):
    if event['action'] == 'sudo' and 'session opened for user root' in event['event_message']:
        stats.count("multi_sudo_session")
        count = stats.getcount("multi_sudo_session")

        if count == 5:
            return 0.25
        elif count == 15:
            return 0.50
        elif count == 30:
            return 0.75
        elif count == 50:
            return 1.0

    return 0.0


def context(event_data):
    count = stats.getcount("multi_sudo_session")
    base = (
        "Detected exactly {count} sudo sessions opened for user root "
        "from IP {ip} on host {host} within the last day.\n\n"
        "Details:\n"
        "- Event Category: {category}\n"
        "- Action: {action}\n"
    ).format(
        count=count,
        ip=event_data['user_ip'],
        host=event_data['host'],
        category=event_data['event_category'],
        action=event_data['action']
    )

    if count == 5:
        explanation = "This level of sudo usage is normal for admin work but tracked for baseline behavior."
    elif count == 15:
        explanation = "This indicates moderate repeated sudo activity, possibly misuse or excessive privileged tasks."
    elif count == 30:
        explanation = "This high number of sudo sessions may suggest suspicious privilege escalation or poor privilege hygiene."
    elif count == 50:
        explanation = "This critical volume of sudo activity strongly indicates potential misuse of privilege escalation or unauthorized root access."
    else:
        explanation = "No defined threshold reached."

    return base + "\nWhy this matters: " + explanation


def criticality():
    count = stats.getcount("multi_sudo_session")
    if count == 5:
        return 'LOW'
    elif count == 15:
        return 'MEDIUM'
    elif count == 30:
        return 'HIGH'
    elif count == 50:
        return 'CRITICAL'

def tactic():
    return 'Privilege Escalation (TA0004)'

def technique():
    return 'Abuse Elevation Control Mechanism (T1548)'

def artifacts():
    return stats.collect(['host', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event['user_ip'], 'type': 'ipaddress'}