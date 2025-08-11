
# Sample name -> streams/Microsoft_Audit/script.py

def configuration():
    return {
    "dictionary": "smc/smc/dictionaries/windows_logs_dictionary/",
    "parsers": "smc/smc/parsers/json_generic/",
    "detections": [
        "smc/smc/detections/vpn_login_from_unusual_geographic_location/",
        "smc/smc/detections/potential_dns_tunneling_command_channel_detected/",
        "smc/smc/detections/suspicious_c2_network_activity_detection/"
    ]
}

def use():
    return 'http://integration-Microsoft-Audit/execute?groups=Windows'
