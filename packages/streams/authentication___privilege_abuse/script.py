
# Sample name -> streams/Microsoft_Audit/script.py

def configuration():
    return {
    "dictionary": "smc/default/dictionaries/windows_logs_dictionary/",
    "detections": [
        "smc/default/detections/excessive_rdp_logins_from_single_source_ip/",
        "smc/default/detections/high_frequency_failed_logons_for_single_account/",
        "smc/default/detections/high_risk_privileges_assigned_during_logon/",
        "smc/default/detections/windows_rare_user_login/"
    ]
}

def use():
    return 'http://integration-Microsoft-Audit/execute?groups=Windows'
