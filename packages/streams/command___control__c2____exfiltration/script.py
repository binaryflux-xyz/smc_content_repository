
# Sample name -> streams/Microsoft_Audit/script.py

def configuration():
    return {
    "dictionary": "smc/default/dictionaries/windows_logs_dictionary/",
    "parsers": "smc/default/parsers/json_generic/",
    "detections": [
        "smc/default/detections/vpn_login_from_unusual_geographic_location/",
        "smc/default/detections/potential_dns_tunneling_command_channel_detected/",
        "smc/default/detections/suspicious_c2_network_activity_detection/"
    ]
}

def use():
    return 'http://integration-Microsoft-Audit/execute?groups=Windows'
