
# Sample name -> streams/Microsoft_Audit/script.py

def configuration():
    return {
    "dictionary": "smc/smc/dictionaries/windows_logs_dictionary/",
    "detections": [
        "smc/smc/detections/unauthorized_access_to_administrative_smb_share/",
        "smc/smc/detections/potential_port_scanning_from_source_ip/",
        "smc/smc/detections/suspicious_new_windows_service_installation_detected/",
        "smc/smc/detections/suspicious_creation_of_windows_scheduled_task/"
    ]
}

def use():
    return 'http://integration-Microsoft-Audit/execute?groups=Windows'
