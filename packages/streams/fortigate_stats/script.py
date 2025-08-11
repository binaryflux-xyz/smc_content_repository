
# Sample name -> streams/fortigate_metrics/script.py

def configuration():
    return {
    "dictionary": "smc/smc/dictionaries/fortigate_firewall_dictionary/",
    "aggregations": [
        "smc/smc/aggregations/fortigate_server_health_status/",
        "smc/smc/aggregations/event_level_stats/"
    ]
}

def use():
    return 'http://integration-fortigate-metrics/execute?groups=operation'
