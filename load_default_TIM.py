from utilities.load_config import load_config

XSOAR_API_KEY="CE4CFD77AA8927C7D9757CE9F83B31F3"
XSOAR_URL="https://54.149.141.61"

load_config(XSOAR_API_KEY=XSOAR_API_KEY,
            XSOAR_URL=XSOAR_URL,
            prompt=False,
            config_file="ipinfo_v2.json",config_dir="example_configs")
