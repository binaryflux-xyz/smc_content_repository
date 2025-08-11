def window():
    return None


def groupby():
    return None

def algorithm(event_data):
    if event_data.get(
        "user_name"
    ) is not None and "local_process_access" in event_data.get("user_name"):
        return 0.75
    return 0.0


def context(event_data):
    os_name = event_data.get("os_name")
    source_ip = event_data.get("source_ip")
    network_protocol = event_data.get("network_protocol")
    destination_country = event_data.get("destination_country")
    destination_ip = event_data.get("destination_ip")
    event_duration = event_data.get("event_duration")
    applicationname = event_data.get("applicationname")
    application_category = event_data.get("application_category")
    application_risk = event_data.get("application_risk")
    policy_type = event_data.get("policy_type")
    policy_id = event_data.get("policy_id")
    user_name = event_data.get("user_name")
    return (
        "A suspicious event involving local process access was detected on " + (os_name if os_name else "None") + 
        ". The user " +( user_name if user_name else "None") + 
        " attempted to access system resources. Source IP: " + (source_ip if source_ip else "None") + 
        ", Destination IP: " + (destination_ip if destination_ip else "None" )+ ", Destination Country: " + 
        (destination_country if destination_country else "None") + 
        ", Protocol: " + (network_protocol if network_protocol else "None" )+ 
        ", Application Name: " +( applicationname if applicationname else "None") + 
        ", Category: " + (application_category if application_category else "None") + 
        ", Risk: " + (application_risk if application_risk else "None") + 
        ", Policy Type: " + (policy_type if policy_type else "None") + 
        ", Policy ID: " + (policy_id if policy_id else "None")+ 
        ", Event Duration: "+ (event_duration if event_duration else "None") + "."
        )
                                      


def criticality():
    return "HIGH"


def tactic():
    return "Initial Access (TA0001)"


def technique():
    return "Exploit Public-Facing Application (T1190)"


def artifacts():
    try:
        return stats.collect(
            ["source_ip", "network_protocol", "destination_ip", "applicationname"]
        )
    except Exception as e:
        raise e


def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
