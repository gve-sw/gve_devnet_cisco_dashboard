# gve_devnet_cisco_dashboard


## Contacts
* Charles Llewellyn

## Solution Components
* Meraki python SDK
* DNA Center SDK
* FMC SDK
* Intersight SDK
* ThousandEyes

## Installation/Configuration
- To the install the dependencies, use pip

```
pip install -r requirements.txt
```

- After installing the dependendencies, make sure to update the .env file with the credentials of Meraki, DNAC, FMC, and Intersight information.

```python
#DNAC 
DNAC_URL = 'dnac.example.com'
DNAC_USERNAME = 'dnacusername'
DNAC_PASSWORD = 'dnacpassword'
#FMC
FMC_URL = 'fmc.example.com'
FMC_USERNAME = 'fmcusername'
FMC_PASSWORD = 'fmcpassword'
#Intersight
INTERSIGHT_API_KEY = ""
# SecretKey file should be stored at the top-level of the projects directory (same level as app.py)
INTERSIGHT_SECRET_FILE = "SecretKey.txt"
#Meraki
MERAKI_API_KEY = ''
# ThousandEyes Widget Embed URL (URL ONLY not iframe)
THOUSAND_EYES_EMBED_URL = ""
```

- Last, run the script and enter the file name as an input. Example below

```
python app.py
```

# Screenshots

![/IMAGES/0image.png](/IMAGES/dashboard0.png)

![/IMAGES/0image.png](/IMAGES/dashboard1.png)

![/IMAGES/0image.png](/IMAGES/0image.png)

### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.
