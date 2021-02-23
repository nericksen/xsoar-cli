import os
import sys
import docker
import requests
import yaml
import json
import subprocess
import shutil
from cmd import Cmd

AVAILABLE_PACKS = ['Nmap','CVESearch','Whois', 'AbuseDB', 'Alexa', 'Confluence', 'Github', 'Gmail', 'HashiCorp-Vault', 'Jira', 'JoeSecurity', 'JsonWhoIs', 'Mattermost', 'MicrosoftTeams', "MongoDB", "OSQuery", "Pwned", "SMB", "Shodan", "Slack", "SplunkPy", "VirusTotal", "WhatIsMyBrowser", "ElasticSearch"]

XSOAR_API_KEY = os.environ['XSOAR_API_KEY']
XSOAR_URL = os.environ['XSOAR_URL']


class XSOARShell(Cmd):
    def __init__(self, **kwargs):
        Cmd.__init__(self, **kwargs)
        self.prompt = "XSOAR:> "
    def do_quit(self, args):
        print("Exiting...")
        raise SystemExit
    def do_packs(self, args):
        """
        List the packs available and enabled
        """
        print("The following Packs are available.  The pack shorthand is used when invoking 'run' command")
        print("\n")
        print("[<state>] <Pack Name> [<pack shorthand>]") 
        print("\n")
        try:
            with open('config.json', 'r') as f:
                CONFIG = json.loads(f.read())
        except Exception as e:
            CONFIG = {}
        for pack in AVAILABLE_PACKS:
            if pack.lower() in CONFIG:
                print(f"[X] {pack} [{pack.lower()}]")
            else:
                print(f"[ ] {pack} [{pack.lower()}]")
    def do_docs(self, args):
        """
        Prints the docs page for a given command or Pack

        Example:
          docs cvesearch
          docs cvesearch cve
        """
        args = args.split(" ")
        pack = args[0]
        if len(args) > 1:
            command = args[1]

        try:
            with open('config.json', 'r') as f:
                CONFIG = json.loads(f.read())
            integration_config_path = CONFIG[pack]['config']
        except Exception as e:
            print("Ensure pack is enabled in order to read the docs")
            print(e)
            return
        

        try:
            with open(integration_config_path, "r") as stream:
                yml = yaml.safe_load(stream)
        except Exception as e:
            print(e)
            return
        print("\n") 
        print("##########")
        print(f" {pack} ")
        print("##########")
        print(f"{yml['description']}")
        print(f"Category: {yml['category']}\n")
        print("Commands\n")
        for item in yml['script']['commands']:
            print(f"Name: {item['name']}")
            if 'description' in item:
                print(f"Description: {item['description']}")
            print("Arguments: ")
            for arg in item['arguments']:
                print(f"\t{arg['name']} ", end="")
                if 'description' in arg:
                    print(f" - {arg['description']}")
            print("\n")

    def do_enable(self, args):
        """
        Enable an integration

        Run this command to enter and save the parameters required to 
        run an integration.
        Parameters will be prompted for.

        SAFE_MODE=true can be passed to require typing the file names
          for the config and code locations in case non standard 
          naming conventions are used.

        Example:
          XSOAR:> enable
        """
        SAFE_MODE = False
        if args:
            args = args.split(" ")
            command = args[0]
            dArgs = {}
            
            for arg in args:
                tmp = arg.split("=")
                k = tmp[0]
                v = tmp[1]

                if "," in v:
                    v = v.split(",")
                else:
                    v = tmp[1]
                dArgs[k] = v
            if 'SAFE_MODE' in dArgs and dArgs['SAFE_MODE'] == 'true':
                SAFE_MODE = True
        print("Enable a pack by entering its <Pack Name> listed by 'packs' command")
        pack = input("Which Pack should be enabled? ")
        config_key = pack.lower()
        try:
            with open('config.json', 'r') as f:
                CONFIG = json.loads(f.read())
        except Exception as e:
            CONFIG = {}
            with open('config.json', 'w+') as f:
                f.write(json.dumps(CONFIG))
        
        if not config_key in CONFIG:
            path = f"content/Packs/{pack}/Integrations/"
            
            # SAFE_MODE if True assumes standard file naming conventions
            if SAFE_MODE:
                print(f"Current integrations in {pack}: ")
                print("\n".join(os.listdir(path)))
                integration = input("Name of the integration: ")
                integration_path = path + integration
                print(f"Files located in {integration_path}")
                print("\n".join(os.listdir(integration_path)))
                integration_code = input("Name of integration code file: ") 
                integration_config = input("Name of integration config file: ")

                integration_code_path = integration_path + '/' + integration_code
                integration_config_path = integration_path + '/' + integration_config
            else:
                integration_path = f"{path}{pack}/"
                integration_code_path = f"{path}{pack}/{pack}.py"
                integration_config_path = f"{path}{pack}/{pack}.yml"
            try:
                with open(integration_config_path, "r") as stream:
                    yml = yaml.safe_load(stream)
            except Exception as e:
                print(e)
                print("\nYou may want to try to enable again with SAFE_MODE=true\n")
                return
                #except yaml.YAMLError as exc:
                #    print(exc)
            #print(yml["configuration"])
            params = {}
            print("Enter integration parameters: \n")
            for param in yml["configuration"]:
                default = param.get('defaultvalue', None)
                if default:
                    params[param['name']] = default
                if 'description' in param:
                    description = param['description']
                else:
                    description = "No description available"
                print(f"{description}\n")
                print(f"Hint Enter for default value ({default})\n")
                tmp_input = input(f"{param['name']}: ")
                if tmp_input:
                    params[param['name']] = tmp_input
                      
            print(params)
            
            mock_param_code = "def params():\n"
            mock_param_code += f"    return {params}\n"    

            #TODO make it optional to save parameters for more security
            # else they will be in plain text, which is ok using credendtial vault
            config = {
                "config": integration_config_path,
                "code": integration_code_path,
                "path": integration_path,
                "params": params,
                "version": "",
                "image_name": f"{config_key}-xsoar"
            }

            CONFIG[config_key] = config
            #################################
            # Sanitze the call to the main function in order to trigger execution ###
            #################################
            lines = []
            with open(integration_code_path) as infile:
                for line in infile:
                    if "__name__" in line and "__main__" not in line:
                        line = "if __name__ in ('__builtin__', 'builtins', '__main__'):\n"
                    lines.append(line)
            with open(integration_code_path, "w") as outfile:
                for line in lines:
                    outfile.write(line)

            ################################
            with open("config.json", "w") as f:
                f.write(json.dumps(CONFIG))

            with open(f"{integration_path}/demistomock_params.py", "w") as f:
                f.write(mock_param_code)

            # Copy CommonServerPython into integration directory
            shutil.copy('content/Packs/Base/Scripts/CommonServerPython/CommonServerPython.py', f"{integration_path}/")
            # Create blank CommonServerUserPython file in integration directory
            open(f"{integration_path}/CommonServerUserPython.py", "a").close()

        else:
            print("Already configured")

    def do_save(self, args):
        """
        Save the integration configuration

        Run this command to enter and save the parameters required to 
        run an integration.
        Parameters will be prompted for.

        Example:
          XSOAR:> save
        """
        with open('config.json', 'r') as f:
            CONFIG = json.loads(f.read())
        #pack_config = CONFIG['ipinfo']
        pack_config = "content/Packs/ipinfo/Integrations/integration-Ipinfo.yml"
        #print(pack_config)
         
        with open(pack_config, "r") as stream:
            try:
                yml = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
        print("\n\n")
        brand = yml["name"]
        config = yml
        #print(config)
        config["integrationScript"] = yml["script"]
        #del config["script"]
        #config["id"] = "CVE Search v2"
        data = []
        for item in yml["configuration"]:
            tmp = item
            prompt = f"Value for {item['name']} " 
            if "defaultvalue" in item:
                prompt += f"(default: {item['defaultvalue']}) "
            prompt += ": "
            tmp["value"] = input(prompt)
            if tmp["name"] == "proxy":
                tmp["defaultValue"] = "False"
                tmp["value"] = "False"
                print(tmp)
                del tmp["defaultvalue"]
            data.append(tmp)
        print("\n\n")
        print(data)
        instance_name = "ipinfo_instance_1"
        body = {
            "name": instance_name, 
            "id": "",
            "engine": "",
            "engineGroup": "",
            "defaultIgnore": False,
            "configuration": {
                "sortValues": None,
                "display": "ipinfo",
                "canGetSamples": True,
                "itemVersion": "1.0.1",
                "brand": "",
                "modified": "2021-01-22T14:15:02.185218921Z",
                "shouldCommit": False,
                "hidden": False,
                "fromServerVersion": "",
                "propagationLabels": [],
                "name": "ipinfo",
                "vcShouldKeepItemLegacyProdMachine": False,
                "system": True,
                "commitMessage": "",
                "vcShouldIgnore": False,
                "packPropagationLabels": ["all"],
                "packID": "ipinfo",
                "configuration": data,
                "version": 1,
                "icon": "",
                "toServerVersion": "",
                "id": yml["commonfields"]["id"],
                "image": "",
                "description": yml["description"],
                "category": yml["category"],
                "prevName": "ipinfo",
                "integrationScript": {
                    "isRemoteSyncOut": False,
                    "longRunning": False,
                    "commands": yml["script"]["commands"],
                    "longRunningPortMapping": False,
                    "isFetchCredentials": False,
                    "runOnce": False,
                    "isRemoteSyncIn": False,
                    "isFetch": False,
                    "isMappable": False,
                    "isFetchSamples": False,
                    "subtype": "",
                    "type": yml["script"]["type"],
                    "feed": False
                },
                "instances": []
            },
            "enabled": "true",
            "propagationLabels": ["all"],
            "data": data,
            "brand": yml["commonfields"]["id"],
            "canSample": True,
            "category": yml["category"],
            "version": 1,
            "isIntegrationScript": True,
            "isLongRunning": False,
            "passwordProtected": False,
            "mappingId": "",
            "incomingMapperId": "",
            "outgoingMapperId": ""
        }

        #use "true" when prompted to trust any cert

        with open("saved/ipinfo.json","w") as f:
            f.write(json.dumps(body))





    def do_load(self,args):
        """
        Load the integration configuration

        Run this command to initialize an integration on an xsoar instance
        with  the parameters saved using the 'save' command

        Example:
          XSOAR:> load
        """
        with open("saved/ipinfo.json", "r") as f:
            body = json.loads(f.read())
        #print(body)
        #with open("body.json", "w+") as f:
        #    f.write(json.dumps(body))
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "Authorization": XSOAR_API_KEY
        }
        print(body)
        res = requests.put(f"{XSOAR_URL}/settings/integration", json=body, headers=headers, verify=False)
        print(res.text)

    def do_run(self, args):
        """
        Run the specified command

        Example:
          XSOAR:> run <pack> <command> <args>
          XSOAR:> run whois whois query=google.com
        """
        args = args.split(" ")
        pack = args[0]
        command = args[1]
        #docker_image = "demisto/ippysocks:1.0.0.11896"
        #command = "whois"
        dArgs = {}
        for arg in args[2:]:
            tmp = arg.split("=")
            k = tmp[0]
            v = tmp[1]
            if "," in v:
                v = v.split(",")
            else:
                v = tmp[1]
            dArgs[k] = v
        #= {"query": "google.com"}
        try:
            with open('config.json', 'r') as f:
                CONFIG = json.loads(f.read())
                print(CONFIG)
            CONFIG[pack]
        except:
            print("Command not configured yet. Try running 'enable' command first")


        with open(CONFIG[pack]["config"], "r") as stream:
            try:
                yml = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)


        docker_image = yml["script"]["dockerimage"]



        mock_command_code = "def command():\n"
        mock_command_code += f"    return '{command}'\n"

        mock_args_code = "def args():\n"
        mock_args_code += f"    return {dArgs}\n"

        mock_results_code = "def results(results):\n"
        mock_results_code += f"    print(results['Contents'])\n"

        mock_results_code += "def error(results):\n"
        mock_results_code += f"    print(str(results))\n"
        mock_results_code += "def info(results):\n"
        mock_results_code += f"    print(str(results))\n"
        mock_results_code += "callingContext = {}\n"

        with open(f"{CONFIG[pack]['path']}/demistomock_params.py", "r") as f:
            mock_params_code = f.read()
        with open(f"{CONFIG[pack]['path']}/demistomock.py", "w") as f:
            f.write(mock_params_code)
            f.write(mock_command_code)
            f.write(mock_args_code)
            f.write(mock_results_code)
        client = docker.from_env()
        volume_path = os.getcwd() + '/' + CONFIG[pack]['path']
        print(volume_path)
        volumes = {
            volume_path: {"bind": "/tmp", "mode": "ro"}
        }
        try:
            container = client.containers.get(container_id=CONFIG[pack]['image_name'])
        except Exception:
            container = None
        if not container:
            container = client.containers.run(docker_image, tty=True, detach=True, name=CONFIG[pack]['image_name'], auto_remove=True, volumes=volumes)
        print(container)
        execute = subprocess.check_output(['docker', 'exec', CONFIG[pack]['image_name'], "/usr/local/bin/python", f"/tmp/{CONFIG[pack]['code'].split('/')[-1]}"], universal_newlines=True)
        print(execute)
        print(execute.replace("'", '"').replace("u\"", '"').replace("\",", "\n").replace("{", "\n").replace("}", "").replace("\\n", "\n").replace("[", "\n").replace("]", "\n").replace(", \"", "\n").replace("\"","").replace("\',","\n"))

if __name__ == '__main__':
    shell = XSOARShell()
    description = "XSOAR CLI utility"

    shell.cmdloop(intro=description)
