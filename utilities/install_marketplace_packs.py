import os
import re
import json
import requests

CONFIG_DIR="/root/xsoar-content"

def install_marketplace_packs(args={}, XSOAR_API_KEY=None, XSOAR_URL=None, XSIAM_MODE=True, pack_list="EXAMPLE_PACK_LIST.txt"):
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
        with open(f"{CONFIG_DIR}/Packs/{pack}/pack_metadata.json", "r") as f:
            pack_metadata = json.loads(f.read())
        print(pack_metadata)
        pack_json = {
            "id": pack,
            "skipInstall": False,
            "transition": None,
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
    install_json["ignoreWarnings"] = False
    install_json["checkBreakingChanges"] = False 
    install_json["transitionPrice"] = 0
    if not XSOAR_API_KEY:
        return "No API key configured for xsoar instance"
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
        "Authorization": XSOAR_API_KEY
    }

    if XSIAM_MODE:
        headers["x-xdr-auth-id"] = "1"
    res = requests.post(f"{XSOAR_URL}/contentpacks/marketplace/install", json=install_json, headers=headers, verify=False)

    if res.ok:
        print(f"Successfully installed packs to {XSOAR_URL}")
    else:
        print(f"Error uploading...{res}: {res.text}")
        if "the following required dependencies are missing " in res.text:
            deps = "\n".join(re.search(r"'(.*?)'", res.text).group(1).replace(" ", "").split(","))
            print(f"Required Dependencies: \n {deps}")
            ans = input("Add missing dependencies to pack install list? Y/n " )
            if ans == "Y":
                with open("EXAMPLE_PACK_LIST.txt", "r+") as f:
                    content = f.read()
                    f.seek(0, 0)
                    #deps = "\n".join(res.text.error.split("the following required dependencies are missing ")[1].split(" "))
                    f.write(deps + '\n' + content)
