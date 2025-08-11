
# Sample name -> streams/Linux_Security/script.py

def configuration():
    return {
    "dictionary": "smc/smc/dictionaries/linux_dictionary/",
    "aggregations": [
        "smc/smc/aggregations/tenant_health_monitor/"
    ]
}

def use():
    return 'http://integration-Linux-Security/execute?groups=OS Events'
