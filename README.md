# XSOAR Command Line Interface
#### The XSOAR Universal CLI
The XSOAR CLI is designed to be a universal cyber security multi tool.
This repo leverages the Demisto content repo [demisto content](https://github.com/demisto/content) where enterprise grade automation content is being built and maintained.
These automation scripts and integrations, combined with the XSOAR CLI make utilizing a vast array of 3rd party and open source APIs from a single CLI possible.


#### Prerequisites
Install python 3.7 or 3.8. 
Clone this repo with `git clone https://github.com/nericksen/xsoar-cli.git`.
Change directory into the CLI repo `cd xsoar-cli`.
Clone the content repo into the same directory `git clone https://github.com/demisto/content.git`.

Recomended to use `pyenv` or another Python versioning tool.

Install `virtualenv` or someother Python virtual environment tool.

For example

`pip install virtualenv`

Create a virtual env with `virtualenv venv`.
Activate the virtualenv with `source ./venv/bin/activate`

Clone the Demisto content repo into the same directory as the XSOAR CLI.



#### Requirements
Install Python3 requirements with `pip install -r requirements.txt`

Install docker engine according to  [here](https://docs.docker.com/get-docker/).

API keys to 3rd party systems you already own or are open source.

## Documentation
The main XSOAR content documentation can be located at: https://xsoar.pan.dev/

Once the dependencies are installed you can run the XSOAR CLI from the root directory of this repository with
`python3 xsoar.py`

You will then be presented with the XSOAR prompt where you can enter CLI commands

Start by viewing the currently available Packs by running `packs` or type `help`.

```
XSOAR:> packs
The following Packs are available.  The pack shorthand is used when invoking 'run' command


<Pack Name> [<pack shorthand>] (<state>)


Nmap [nmap]
CVESearch [cvesearch]
Whois [whois]
AbuseDB [abusedb]
Alexa [alexa]
Confluence [confluence]
Github [github]
Gmail [gmail]
HashiCorp-Vault [hashicorp-vault]
Jira [jira]
JoeSecurity [joesecurity]
JsonWhoIs [jsonwhois]
Mattermost [mattermost]
MicrosoftTeams [microsoftteams]
MongoDB [mongodb]
OSQuery [osquery]
Pwned [pwned]
SMB [smb]
Shodan [shodan]
Slack [slack]
SplunkPy [splunkpy]
VirusTotal [virustotal]
WhatIsMyBrowser [whatismybrowser]
ElasticSearch [elasticsearch]
```
Enabling a pack allows for entering the parameters needed for authenticating to the 3rd party service and can be performed with `enable <Pack Name>`.

```
XSOAR:> enable
Enable a pack by entering its <Pack Name> listed by 'packs' command
Which Pack should be enabled? Whois
Enter integration parameters: 

No description available

Hint Enter for default value (None)

with_error: 
No description available

Hint Enter for default value (None)

proxy_url: 
{}
```

If the pack does not following the standard XSOAR naming conventions it may not be located, in which case you can run `enable` command again with `SAFE_MODE=true`.

```
XSOAR:>enable SAFE_MODE=true
```

Once the pack is enabled you can run its commads using the `run` command.
```
XSOAR:> run whois whois query=ask.com

status: 
clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
 clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
 clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
 serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)
 serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)
 serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)

updated_date: 
datetime.datetime(2019, 3, 5, 10, 59, 3)

contacts: 
admin: 
country: US
 state: CA
 name: Ask.com
tech: 
organization: Ask.com
 state: CA
 country: US
registrant: 
.
.
.
```


Listing the commands for a pack can be accomplished by using the `docs command`.

```
XSOAR:> docs whois


##########
 whois 
##########
Provides data enrichment for domains.
Category: Data Enrichment & Threat Intelligence

Commands

Name: whois
Description: Provides data enrichment for domains.
Arguments: 
	query  - The domain to enrich.


Name: domain
Description: Provides data enrichment for domains.
Arguments: 
	domain  - The domain to enrich.

```


#### Currently Tested Packs
```
[x] Nmap
[x] CVESearch
[x] Whois
[] AbuseDB 
[x] Alexa
[] Confluence
[] Github
[] Gmail
[] HashiCorp-Vault
[] Jira
[] JoeSecurity
[] JsonWhoIs
[] Mattermost
[] MicrosoftTeams
[] MongoDB
[] OSQuery
[] Pwned
[] SMB
[] Shodan
[] Slack
[] SplunkPy
[] VirusTotal
[] WhatIsMyBrowser
[] ElasticSearch
```

#### Integration Notes
It is important to note that the Pack in question must contain the check for `__main__` as `__name__` in order for the python code to actually execute.
Currently only Python modules are supported. 

```
if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
```

Currently the `enable` command will work to add `__main__` if it does not exist in the pack code.

You can set `insecure: True` when prompted to not validate the SSL cert with http requests.

#### Next in line for support
* AWS Packs
* GCP Packs
* Azure Packs

#### Packs Configurations
Pack configurations are stored in the config.json that is created in the root of this repo directory.
You can remove this file at anytime to disable all intergations.
As this file contains secrets and API keys it is strongly advised to manage its access closely.

#### Known Limitations
Currently only python modules are supported.
The file path within the docker container for execution is hardcoded to be `/usr/bin/python`.

#### Future Improvements
[] Place generated demistomock, commonserverpython, commonserveruserpython into tmp directory not tracked by version control.


