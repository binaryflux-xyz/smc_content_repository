
# Sample name -> streams/Linux_Security/script.py

def configuration():
    return {
    "dictionary": "smc/default/dictionaries/linux_dictionary/"
}

def use():
    return 'http://integration-Linux-Security/execute?groups=OS Events'
