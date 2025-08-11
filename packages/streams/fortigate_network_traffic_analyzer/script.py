# sample name -> streams/gsuite_google_drive/script.py

def configuration():
    return {
        'dictionary': 'smc/smc/dictionaries/fortigate_firewall_dictionary/',
        'parsers': 'smc/smc/parsers/fortigate/',
        'filters': ['smc/smc/filters/network_traffic_filter/',
                    'smc/smc/filters/application_control_web_filter/'],
        'transformations': ['smc/smc/transformations/packet_transferred/'],
        # 'correlation': 'customer/tenant/correlations/folder-name/',
        'detections': ['smc/smc/detections/abnormal_dns_traffic/',
                       'smc/smc/detections/abnormal_traffic_covert_channel/',
                       'smc/smc/detections/authentication_bypass/',
                       'smc/smc/detections/beaconing_traffic_malicious_sites/',
                       'smc/smc/detections/traffic_known_malicious_domains/',
                       'smc/smc/detections/app_access_moniter_NONE/'],
        # 'sequences': ['customer/tenant/sequences/folder-name/'],
        'automations': ['smc/smc/automations/countries_with_most_detections/'],
        'reports':['smc/smc/reports/fortigate_vpn_daily_reports/'],
        'aggregations':['smc/smc/aggregations/countries_with_most_detections/',
                        'smc/smc/aggregations/accounts_with_most_detections/',
                        'smc/smc/aggregations/apps_with_most_detections/',
                        'smc/smc/aggregations/entity_app_frequency/',
                        'smc/smc/aggregations/high_usage_connection/',
                        'smc/smc/aggregations/hosts_with_most_detections/',
                        'smc/smc/aggregations/top_entity_hostname_contributions/',
                        'smc/smc/aggregations/trafic_exchange_logs/']
    }




def use():
    return 'http://integration-fortigate-metrics/execute?groups=operation&client_id=$.INTEGRATION_kubernetes_node_metrics_AUTHORIZATION_CLIENTID&client_secret=$.INTEGRATION_kubernetes_node_metrics_AUTHORIZATION_CLIENTSECRET&account_id=$.INTEGRATION_kubernetes_node_metrics_AUTHORIZATION_ACCOUNTID&frequency=1d'
