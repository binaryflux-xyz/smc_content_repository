
# Sample name -> streams/Microsoft_Audit/script.py

def configuration():
    return {
    "dictionary": "smc/default/dictionaries/windows_logs_dictionary/",
    "detections": [
        "smc/default/detections/unauthorized_access_to_administrative_smb_share/",
        "smc/default/detections/potential_port_scanning_from_source_ip/",
        "smc/default/detections/suspicious_new_windows_service_installation_detected/",
        "smc/default/detections/suspicious_creation_of_windows_scheduled_task/"
    ]
}

def use():
    return 'http://integration-Microsoft-Audit/execute?groups=Windows'
