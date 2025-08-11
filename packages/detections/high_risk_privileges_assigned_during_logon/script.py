def window():
    return '1d'  # Add a 1-day window so counts make sense

def groupby():
    return ['source_account_name']  # Group by user account
  
def algorithm(event):
    # Ensure it's Event ID 4672 (Special Logon)
    if event.get('event_id') != 4672:
        return 0.0  # Ignore other events

    # Extract key fields
    user = event.get("source_account_name", "").lower()
    privileges = [priv.lower() for priv in event.get("privileges", [])]

    # List of known system accounts to ignore
    ignored_accounts = ["system", "local service", "network service", "administrator","SANAKA$"]

    # List of high-risk privileges
    critical_privileges = [
        "sedebugprivilege",
        "seimpersonateprivilege",
        "setakeownershipprivilege",
        "seloaddriverprivilege"
    ]

    # Ignore known system accounts
    if user in ignored_accounts:
        return 0.0  # Ignore system accounts

    # Only trigger if high-risk privileges are assigned
    if any(priv in privileges for priv in critical_privileges):
        stats.count("high_risk_privileges_assigned")
        count = stats.getcount("high_risk_privileges_assigned")

        if count == 2:
            return 0.25
        elif count == 10:
            return 0.50
        elif count == 20:
            return 0.75
        elif count == 50:
            return 1.0
        else:
            return 0.0

    return 0.0

  
def context(event_data):
    count = stats.getcount("high_risk_privileges_assigned")

    base = (
        "High-risk admin privileges were assigned to user '{user}' "
        "from domain '{domain}' on device '{host}'.\n\n"
        "Event ID: {event_id}\n"
        "Privileges: {privileges}\n"
    ).format(
        user=event_data.get('source_account_name', 'Unknown'),
        domain=event_data.get('source_account_domain', 'Unknown'),
        host=event_data.get('host', 'Unknown'),
        event_id=event_data.get('event_id', 'Unknown'),
        privileges=", ".join(event_data.get('privileges', []))
    )

    if count == 2:
        summary = "Single instance detected. Monitoring recommended."
    elif count == 10:
        summary = "Pattern forming: elevated privileges assigned multiple times."
    elif count == 20:
        summary = "Frequent privilege assignments detected. Investigation advised."
    elif count == 50:
        summary = "Critical activity spike — likely privilege escalation behavior."
    else:
        return None

    return base + "\n" + summary

  
def criticality():
    count = stats.getcount("high_risk_privileges_assigned")
    if count == 2:
        return 'LOW'
    elif count == 10:
        return 'MEDIUM'
    elif count == 20:
        return 'HIGH'
    elif count == 50:
        return 'CRITICAL'
    else:
        return None
      
def tactic():
    return 'Privilege Escalation (TA0004)'
  
def technique():
    return "Access Token Manipulation (T1134)"
  
def artifacts():
    return stats.collect(['host', 'source_account_name', "event_id", "privileges"])
  
def entity(event):
    return {'derived': False, 'value': event['source_account_name'], 'type': 'accountname'}