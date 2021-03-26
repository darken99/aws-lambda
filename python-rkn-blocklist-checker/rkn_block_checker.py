from collections import defaultdict

import boto3
import codecs
import csv
import json
import ipaddress
import urllib.request
import socket

blocked_prefixes = None


# Download current JSON data from Amazon
def downloadJSONdata():

    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    response = urllib.request.urlopen(url)
    content = response.read()
    data = []
    for prefix in json.loads(content)['prefixes']:
        try:
            data.append(ipaddress.ip_network(prefix['ip_prefix']))
        except ValueError:
            continue

    prefixes = [ipaddr for ipaddr in ipaddress.collapse_addresses(data)]
    return prefixes


# Download current RKN data from GitHub
def getRKNdata():
    # Get AWS prefixes
    aws_prefixes = downloadJSONdata()

    url = "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv"
    data = []

    response = urllib.request.urlopen(url)
    reader = csv.reader(codecs.iterdecode(response, 'cp1251'), delimiter=';')

    for row in reader:
        for rkn_prefix in row[0].split(' | '):
            try:
                data.append(ipaddress.ip_network(rkn_prefix))
            except ValueError:
                # Not an IP in rkn_blocklist row
                continue

    rkn_prefixes = [ipaddr for ipaddr in ipaddress.collapse_addresses(data)]

    data = []

    for aws_prefix in aws_prefixes:
        for rkn_prefix in rkn_prefixes:
            if rkn_prefix.overlaps(aws_prefix):
                data.append(rkn_prefix)
                break

    return [ipaddr for ipaddr in ipaddress.collapse_addresses(data)]


def getIPx(d):
    """
    This method returns an array containing
    one or more IP address strings that respond
    as the given domain name
    """
    try:
        data = socket.gethostbyname_ex(d)
        ipx = data[2]
        return ipx
    except Exception:
        # fail gracefully!
        return False


def checkIP(ip):
    global blocked_prefixes
    if blocked_prefixes is None:
        blocked_prefixes = getRKNdata()
    for prefix in blocked_prefixes:
        if ipaddress.ip_address(ip) in prefix:
            return prefix
    return None


def lambda_handler(event, context):
    """
    A tool for checking if EC2/EIP/ELB/ALB is in RKN blocklist.
    """
    blocked_resources = 0
    # Connect to EC2
    ec2 = boto3.client('ec2')

    # Retrieves all regions/endpoints that work with EC2
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

    for region in regions:
        ec2 = boto3.resource('ec2', region)
        ec2c = boto3.client('ec2', region)
        elb = boto3.client('elb', region)
        elbv2 = boto3.client('elbv2', region)

        # Get information for all running EC2 instances
        running_instances = ec2.instances.filter(Filters=[{
            'Name': 'instance-state-name',
            'Values': ['running']}])

        ec2info = defaultdict()
        for instance in running_instances:
            for tag in instance.tags:
                if 'Name'in tag['Key']:
                    name = tag['Value']
            # Add instance info to a dictionary
            ec2info[instance.id] = {
                'Name': name,
                'Type': instance.instance_type,
                'State': instance.state['Name'],
                'Private IP': instance.private_ip_address,
                'Public IP': instance.public_ip_address,
                'Launch Time': instance.launch_time
            }
            result = checkIP(instance.public_ip_address)
            if result is not None:
                blocked_resources += 1
                print("EC2 instance '{id}' in '{region}', public IP '{public_ip}' blocked in: '{prefix}'".format(prefix=result, region=region, public_ip=instance.public_ip_address, id=instance.id))

        # Network Interfaces
        addresses_dict = ec2c.describe_addresses()
        for eip_dict in addresses_dict['Addresses']:
            if "NetworkInterfaceId" in eip_dict:
                result = checkIP(eip_dict['PublicIp'])
                if result is not None:
                    blocked_resources += 1
                    print("EIP '{eip}' in '{region}' blocked in: '{prefix}'".format(prefix=result, region=region, eip=eip_dict['PublicIp']))

        # CLB
        elbs = elb.describe_load_balancers()
        for elb in elbs['LoadBalancerDescriptions']:
            ips = getIPx(elb['DNSName'])
            for ip in ips:
                result = checkIP(ip)
                if result is not None:
                    blocked_resources += 1
                    print("ELB '{name}' in '{region}', blocked ip: '{ip}', blocked in: '{prefix}'".format(name=elb['LoadBalancerName'], ip=ip, region=region, prefix=result))

        # ALB
        elbs = elbv2.describe_load_balancers()
        for elb in elbs['LoadBalancers']:
            ips = getIPx(elb['DNSName'])
            for ip in ips:
                result = checkIP(ip)
                if result is not None:
                    blocked_resources += 1
                    print("ELBv2 '{name}' ({type}) in '{region}', blocked ip: '{ip}', blocked in: '{prefix}'".format(name=elb['LoadBalancerName'], ip=ip, region=region, prefix=result, type=elb['Type']))

    return "Number of blocked resources: {0}".format(blocked_resources)
