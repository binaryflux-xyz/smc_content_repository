
# Sample name -> streams/Linux_Security/script.py

def configuration():
    return {
    "dictionary": "smc/default/dictionaries/linux_dictionary/",
    "aggregations": [
        "smc/default/aggregations/tenant_health_monitor/"
    ]
}

def use():
    return 'http://integration-Linux-Security/execute?groups=OS Events'
