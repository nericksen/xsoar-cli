import os
import requests

VAULT_TOKEN = os.environ['VAULT_TOKEN']
VAULT_URL = os.environ['VAULT_URL']

def request_vault_credentials(VAULT_TOKEN,VAULT_URL,VAULT_ENGINE,SECRET):
    URL = f"{VAULT_URL}/v1/{VAULT_ENGINE}/data/{SECRET}"
    HEADERS = {
        "X-Vault-Token": VAULT_TOKEN
    }
    
    params = {
        "version": 2
    }
    
    res = requests.get(URL, headers=HEADERS, verify=False)
    
    print(res)
    print(res.status_code)
    print(res.content)
    return res.json()

request_vault_credentials(VAULT_TOKEN,VAULT_URL,"kv","abuseipdb")
