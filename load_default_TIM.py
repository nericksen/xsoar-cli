import os
import time
from utilities.load_config import load_config


SAVED_DIR="saved"

XSOAR_API_KEY = os.environ['XSOAR_API_KEY']
XSOAR_URL = os.environ['XSOAR_URL']
#VAULT_TOKEN = os.environ['VAULT_TOKEN']
#VAULT_URL = os.environ['VAULT_URL']
config_dir = f"{SAVED_DIR}"
saved_configs = os.listdir(config_dir)

for config in saved_configs:
    print(config)
    load_config(XSOAR_API_KEY=XSOAR_API_KEY,
                XSOAR_URL=XSOAR_URL,
                prompt=False,
                config_file=config,
                config_dir=config_dir,
                VAULT_TOKEN=None,
                VAULT_URL=None)
    print("Sleeping while the first fetch happens...")
    time.sleep(120)
