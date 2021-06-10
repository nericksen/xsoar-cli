import os
import json
import requests

def load_config(args={}, XSOAR_API_KEY=None, XSOAR_URL=None, prompt=True, config_dir="saved", config_file=None):
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
    
    #print(body)
    #with open("body.json", "w+") as f:
    #    f.write(json.dumps(body))
    if not XSOAR_API_KEY:
        return "No API key configured for xsoar instance"
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
        "Authorization": XSOAR_API_KEY
    }
    res = requests.put(f"{XSOAR_URL}/settings/integration", json=body, headers=headers, verify=False)

    if res.ok:
        print(f"Successfully uploaded {selected_config_file} to {XSOAR_URL}")
    else:
        print(f"Error uploading...{res.text}")
