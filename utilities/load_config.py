import os
import json
import requests

def request_vault_credentials(VAULT_TOKEN,VAULT_URL,VAULT_ENGINE,SECRET):
    URL = f"{VAULT_URL}/v1/{VAULT_ENGINE}/data/{SECRET}"
    HEADERS = {
        "X-Vault-Token": VAULT_TOKEN
    }
    
    params = {
        "version": 2
    }
    
    res = requests.get(URL, headers=HEADERS, verify=False)
    
    return res.json()

def load_config(args={},XSIAM_MODE=True, XSOAR_API_KEY=None, XSOAR_URL=None, prompt=True, config_dir="saved", config_file=None, HASHIVAULT=False,VAULT_TOKEN=None,VAULT_URL=None):
    """
    Load the integration configuration

    Run this command to initialize an integration on an xsoar instance
    with  the parameters saved using the 'save' command

    Example:
      XSOAR:> load
    """
    # Print all saved configs
    saved_configs = os.listdir(config_dir)
    if len(saved_configs) == 0:
        return "No saved configs. Run save command first"
    for index, config in enumerate(saved_configs):
        print(f"{[index]} {config}")
    if prompt:
        selected_index = input("Which config should be loaded (input number from above)? ")
        selected_config_file = saved_configs[int(selected_index)]
        instance_name = input("Enter the instance name to create: ")
    else:
        selected_config_file = config_file
        instance_name = config_file.split(".json")[0]
    with open(f"{config_dir}/{selected_config_file}", "r") as f:
        print(config_dir)
        print(selected_config_file)
        body = json.loads(f.read())
    
    body["name"] = instance_name
    
    # check to make request for hashivault creds
    #TODO make this a seperate function or reduce the need to call the
    # vault api twice to update the config
    #HASHIVAULT = True
    if HASHIVAULT:
        data = body["configuration"]["configuration"]
        for item in data:
            if "value" in item and "HASHIVAULT" in item["value"]:
                # if the vaule is stored as HASHIVAULT.engine.secret.KEY
                # the secret can be requested and passed
                vault_entry = item["value"].split(".")
                secret_engine = vault_entry[1]
                secret_name = vault_entry[2]
                secret_key = vault_entry[3]
                item["value"] = request_vault_credentials(VAULT_TOKEN,VAULT_URL,secret_engine,secret_name)["data"]["data"][secret_key]
        data = body["data"]
        for item in data:
            if "value" in item and "HASHIVAULT" in item["value"]:
                # if the vaule is stored as HASHIVAULT.engine.secret.KEY
                # the secret can be requested and passed
                vault_entry = item["value"].split(".")
                secret_engine = vault_entry[1]
                secret_name = vault_entry[2]
                secret_key = vault_entry[3]
                print(f"Requesting from Vault: {item['value']}")
                item["value"] = request_vault_credentials(VAULT_TOKEN,VAULT_URL,secret_engine,secret_name)["data"]["data"][secret_key]

    print(body)
    #with open("body.json", "w+") as f:
    #    f.write(json.dumps(body))
    if not XSOAR_API_KEY:
        return "No API key configured for xsoar instance"
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
        "Authorization": XSOAR_API_KEY
    }

    if XSIAM_MODE:
        headers["x-xdr-auth-id"] = "1"
    res = requests.put(f"{XSOAR_URL}/settings/integration", json=body, headers=headers, verify=False)

    if res.ok:
        print(f"Successfully uploaded {selected_config_file} to {XSOAR_URL}")
    else:
        print(f"Error uploading...{res.text}")
