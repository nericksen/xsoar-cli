import os
from utilities.install_marketplace_packs import install_marketplace_packs

XSOAR_API_KEY = os.environ['XSOAR_API_KEY']
XSOAR_URL = os.environ['XSOAR_URL']

install_marketplace_packs(XSOAR_API_KEY=XSOAR_API_KEY,
                          XSOAR_URL=XSOAR_URL,
                          pack_list="EXAMPLE_PACK_LIST.txt")
