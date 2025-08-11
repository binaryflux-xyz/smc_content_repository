
# Sample name -> streams/Microsoft_Audit/script.py

def configuration():
    return {
    "dictionary": "smc/smc/dictionaries/windows_logs_dictionary/",
    "detections": [
        "smc/smc/detections/excessive_rdp_logins_from_single_source_ip/",
        "smc/smc/detections/high_frequency_failed_logons_for_single_account/",
        "smc/smc/detections/high_risk_privileges_assigned_during_logon/",
        "smc/smc/detections/windows_rare_user_login/"
    ]
}

def use():
    return 'http://integration-Microsoft-Audit/execute?groups=Windows'
