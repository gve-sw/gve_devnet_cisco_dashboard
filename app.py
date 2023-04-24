"""
Copyright (c) 2020 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""
from flask import Flask, render_template, request
from flask_caching import Cache
from dnacentersdk import DNACenterAPI
import fmcapi
from fmcapi import *
import intersight
import intersight.api.compute_api
import intersight.api.hyperflex_api
import re
import meraki
from dotenv import load_dotenv
import os


load_dotenv()
DNAC_URL = os.getenv('DNAC_URL')
DNAC_USERNAME = os.getenv('DNAC_USERNAME')
DNAC_PASSWORD = os.getenv('DNAC_PASSWORD')
FMC_URL = os.getenv('FMC_URL')
FMC_USERNAME = os.getenv('FMC_USERNAME')
FMC_PASSWORD = os.getenv('FMC_PASSWORD')
INTERSIGHT_API_KEY = os.getenv('INTERSIGHT_API_KEY')
INTERSIGHT_SECRET_FILE = os.getenv('INTERSIGHT_SECRET_FILE')
MERAKI_API_KEY = os.getenv('MERAKI_API_KEY')
THOUSAND_EYES_EMBED_URL = os.getenv('THOUSAND_EYES_EMBED_URL')
# Initialize Flask app
app = Flask(__name__)

# Configure Flask-Caching
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# Initialize DNAC SDK with verify=False to bypass SSL certificate verification
dnac = DNACenterAPI(username=DNAC_USERNAME, password=DNAC_PASSWORD, base_url=DNAC_URL, verify=False)

# Create a function to get devices and cache the result
@cache.memoize(timeout=300)  # Cache the result for 5 minutes (300 seconds)
def get_dnac_devices():
    devices_data = dnac.devices.get_device_list(family=("Routers", "Switches and Hubs"))
    devices = [
        {
            'id': device["id"],
            'hostname': device["hostname"],
            'family': "Switches" if device["family"] == "Switches and Hubs" else device["family"],
            'softwareType': device["softwareType"],
            'softwareVersion': device["softwareVersion"],
            'managementIpAddress': device["managementIpAddress"],
            'reachabilityStatus': device["reachabilityStatus"],
            "health": "Healthy" if device["reachabilityStatus"] == "Reachable" else device["reachabilityStatus"],
            "url": f"{DNAC_URL}/dna/assurance/device/details?id={device['id']}",
        } for device in devices_data.response
    ]
    return devices

@cache.memoize(timeout=300)  # Cache the result for 5 minutes (300 seconds)
def get_fmc_devices():
    try:
        with fmcapi.FMC(host=FMC_URL, username=FMC_USERNAME, password=FMC_PASSWORD, autodeploy=False, timeout=5) as fmc:
            devices = DeviceRecords(fmc).get()
            if devices['items']:
                firewalls = [
                    {
                        "hostname": device["name"],
                        "family": "Firewalls",
                        "reachabilityStatus": "Unreachable" if device["healthStatus"] == "disabled" else "Reachable",
                        "softwareType": device["model"],
                        "managementIpAddress": device["hostName"],
                        "health": "Healthy" if device["healthStatus"] != "disabled" else device["healthMessage"],
                        "url": "#",
                    } for device in devices['items']
                ]
            else:
                firewalls = []
    except Exception as e:
        firewalls = []
    return firewalls


def get_intersight_api_client(api_key_id=INTERSIGHT_API_KEY, api_secret_file=INTERSIGHT_SECRET_FILE, endpoint="https://intersight.com"):
    with open(api_secret_file, 'r') as f:
        api_key = f.read()

    if re.search('BEGIN RSA PRIVATE KEY', api_key):
        # API Key v2 format
        signing_algorithm = intersight.signing.ALGORITHM_RSASSA_PKCS1v15
        signing_scheme = intersight.signing.SCHEME_RSA_SHA256
        hash_algorithm = intersight.signing.HASH_SHA256

    elif re.search('BEGIN EC PRIVATE KEY', api_key):
        # API Key v3 format
        signing_algorithm = intersight.signing.ALGORITHM_ECDSA_MODE_DETERMINISTIC_RFC6979
        signing_scheme = intersight.signing.SCHEME_HS2019
        hash_algorithm = intersight.signing.HASH_SHA256

    configuration = intersight.Configuration(
        host=endpoint,
        signing_info=intersight.signing.HttpSigningConfiguration(
            key_id=api_key_id,
            private_key_path=api_secret_file,
            signing_scheme=signing_scheme,
            signing_algorithm=signing_algorithm,
            hash_algorithm=hash_algorithm,
            signed_headers=[
                intersight.signing.HEADER_REQUEST_TARGET,
                intersight.signing.HEADER_HOST,
                intersight.signing.HEADER_DATE,
                intersight.signing.HEADER_DIGEST,
            ]
        )
    )

    # if you want to turn off certificate verification
    # configuration.verify_ssl = False

    return intersight.ApiClient(configuration)
@cache.memoize(timeout=300)  # Cache the result for 5 minutes (300 seconds)
def get_servers():
    def get_device_status(device):
        if isinstance(device,intersight.model.compute_physical_summary.ComputePhysicalSummary):
            status = "Unreachable" if device.oper_power_state != "on" else "Reachable"
        else:
            status = "Unreachable" if device.summary.state != "ONLINE" else "Reachable"

        return status
    # Get the Intersight API client
    api_client = get_intersight_api_client()

    # Get the compute inventory
    compute_api_instance = intersight.api.compute_api.ComputeApi(api_client)
    compute_inventory = compute_api_instance.get_compute_physical_summary_list(filter='contains(Model,\'UCSX\')')
    compute_devices = compute_inventory.results

    # Get the HyperFlex inventory
    hyperflex_api_instance = intersight.api.hyperflex_api.HyperflexApi(api_client)
    hyperflex_inventory = hyperflex_api_instance.get_hyperflex_cluster_list()
    hyperflex_clusters = hyperflex_inventory.results

    # Combine the physical servers and HyperFlex clusters into a single list of devices
    devices = compute_devices + hyperflex_clusters

    # Create a list of dictionaries representing each device
    servers = [
        {
            "health": device.alarm_summary.health,
            "hostname": device.name,
            "family": "Servers" if isinstance(device,
                                              intersight.model.compute_physical_summary.ComputePhysicalSummary) else "HyperFlex",
            "reachabilityStatus": get_device_status(device),
            "softwareType": device.model if isinstance(device, intersight.model.compute_physical_summary.ComputePhysicalSummary) else device["hypervisor_type"],
            "managementIpAddress": device.mgmt_ip_address if isinstance(device, intersight.model.compute_physical_summary.ComputePhysicalSummary) else "N/A",
            "url": f"https://www.intersight.com/an/infrastructure-service/an/{'compute' if isinstance(device, intersight.model.compute_physical_summary.ComputePhysicalSummary) else 'hyperflex'}/{'physical-summaries' if isinstance(device, intersight.model.compute_physical_summary.ComputePhysicalSummary) else 'clusters/cluster'}/{device['moid']}",
        } for device in devices
    ]
    return servers


@cache.cached(key_prefix='meraki_devices')
def get_meraki_devices(meraki_client, org_id):
    # Get all networks in the organization
    networks = meraki_client.organizations.getOrganizationNetworks(org_id)

    meraki_devices = []

    for network in networks:
        network_devices = meraki_client.networks.getNetworkDevices(network['id'])
        meraki_devices.extend(network_devices)

    network_device_statuses = meraki_client.organizations.getOrganizationDevicesStatuses(org_id, total_pages="all")

    l1_dict = {item['serial']: item for item in meraki_devices}
    l2_dict = {item['serial']: item for item in network_device_statuses}

    for item in l1_dict:
        l1_dict[item].update(l2_dict.get(item, {}))

    network_devices = list(l1_dict.values())

    devices = [
        {
            "reachabilityStatus" : "Reachable" if device["status"] == "online" else "Unreachable",
            "softwareType": device["firmware"],
            "managementIpAddress": device["publicIp"],
            "health": "Healthy" if device["status"] == "online" else device["status"].capitalize(),
            "hostname": device["serial"],
            "family": "Meraki",
            "url": device["url"],
        } for device in network_devices
    ]
    return devices


@app.route('/')
def list_devices():
    # Get query parameters for pagination
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)

    # Get all DNAC devices using the cached function
    dnac_devices = get_dnac_devices()
    # Get firewall devices
    fmc_devices = get_fmc_devices()
    # Get intersite devices
    is_servers = get_servers()
    # Get Meraki Devices
    meraki_client = meraki.DashboardAPI(MERAKI_API_KEY, suppress_logging=True)
    ORG_ID = '965749'
    meraki_devices = get_meraki_devices(meraki_client, org_id=ORG_ID)


    devices = dnac_devices+fmc_devices+is_servers+meraki_devices

    routers = {"online":0, "offline":0}
    switches = {"online":0, "offline":0}
    firewalls = {"online":0, "offline":0}
    servers = {"online":0, "offline":0}
    meraki_d = {"online":0, "offline":0}

    for device in dnac_devices:
        if device["family"] == "Switches":
            if device["reachabilityStatus"] == "Reachable":
                switches["online"] += 1
            else:
                switches["offline"] += 1
        if device["family"] == "Routers":
            if device["reachabilityStatus"] == "Reachable":
                routers["online"] += 1
            else:
                routers["offline"] += 1

    for firewall in fmc_devices:
        if firewall["reachabilityStatus"] == "Reachable":
            firewalls["online"] += 1
        else:
            firewalls["offline"] += 1

    for server in is_servers:
        if server["reachabilityStatus"] == "Reachable":
            servers["online"] += 1
        else:
            servers["offline"] += 1
    for device in meraki_devices:
        if device["reachabilityStatus"] == "Reachable":
            meraki_d["online"] += 1
        else:
            meraki_d["offline"] += 1

    # Paginate devices list
    paginated_devices = devices[(page - 1) * per_page: page * per_page]
    total_pages = -(-len(devices) // per_page)  # Calculate total pages using ceiling division

    # Render the HTML template with the paginated devices data
    return render_template('devices_styled.html', devices=paginated_devices, current_page=page, total_pages=total_pages,
                           routers=routers, switches=switches, firewalls=firewalls, servers=servers, meraki=meraki_d, te_embed_url=THOUSAND_EYES_EMBED_URL)
if __name__ == '__main__':
    app.run(debug=True)
