import os
import json
import requests

def install_marketplace_packs(args={}, XSOAR_API_KEY=None, XSOAR_URL=None, pack_list="EXAMPLE_PACK_LIST.txt"):
    """
    Install marketplace content packs
    """
    # Print all saved configs
    with open(pack_list, "r") as f:
        packs = f.read().split("\n")

    install_json = {}
    install_json["packs"] = []
    for pack in packs:
        if not pack:
            continue
        with open(f"content/Packs/{pack}/pack_metadata.json", "r") as f:
            pack_metadata = json.loads(f.read())
        print(pack_metadata)
        pack_json = {
            "id": pack,
            "skipInstall": False,
            "version": pack_metadata.get("currentVersion")
        }
        install_json["packs"].append(pack_json)
    """
    install_json = {
        "packs": [
            {
                "id": "FeedFeodoTracker",
                "skipInstall": False,
                "version": "1.1.3"
            }
        ]
    }
    """
    
    if not XSOAR_API_KEY:
        return "No API key configured for xsoar instance"
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
        "Authorization": XSOAR_API_KEY
    }
    res = requests.post(f"{XSOAR_URL}/contentpacks/marketplace/install", json=install_json, headers=headers, verify=False)

    if res.ok:
        print(f"Successfully installed packs to {XSOAR_URL}")
    else:
        print(f"Error uploading...{res.text}")
