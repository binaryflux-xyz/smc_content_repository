
# Sample name -> streams/Microsoft_Audit/script.py

def configuration():
    return {
    "dictionary": "smc/smc/dictionaries/windows_logs_dictionary/",
    "aggregations": [
        "smc/smc/aggregations/tenant_health_monitor/"
    ]
}

def use():
    return 'http://integration-Microsoft-Audit/execute?groups=Windows Events'
