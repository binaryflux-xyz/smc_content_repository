
# Sample name -> streams/Microsoft_Audit/script.py

def configuration():
    return {
    "dictionary": "smc/default/dictionaries/windows_logs_dictionary/",
    "detections": [
        "smc/default/detections/attempt_to_disable_windows_event_logging_via_powershell/",
        "smc/default/detections/windows_firewall_rule_misconfiguration_and_parsing_errors/"
    ]
}

def use():
    return 'http://integration-Microsoft-Audit/execute?groups=Windows'
