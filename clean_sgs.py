import json
import subprocess
import boto3
import argparse

def get_findings(severity):
    command = [
        "aws",
        "--region",
        "eu-west-1",
        "securityhub",
        "get-findings",
        "--filters",
        f'{{"SeverityLabel":[{{"Value":"{severity}","Comparison":"EQUALS"}}]}}'
    ]

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        findings = json.loads(output)
        with open("findings.json", "w") as f:
            json.dump(findings, f, indent=4)

        return findings
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None


def parse_security_groups(findings):
    security_groups = []
    print(f"NUMBER OF FINDINGS IS {len(findings.get("Findings", []))}")
    for finding in findings.get("Findings", []):
        resources = finding.get("Resources", [])

        for resource in resources:
            if resource.get("Type") == "AwsEc2SecurityGroup":
                details = resource.get("Details", {}).get("AwsEc2SecurityGroup", {})
                group_name = details.get("GroupName")
                group_id = details.get("GroupId")
                if group_name and group_id:
                    security_groups.append({"GroupName": group_name, "GroupId": group_id, "region": resource.get("Region")})
            else:
                print(f"RESOURCE NOT A SECURITY GROUP: {resource.get("Type")}")

    return security_groups

def describe_network_interfaces(group_id):
    command = [
        "aws",
        "ec2",
        "describe-network-interfaces",
        "--filters",
        f"Name=group-id,Values={group_id}",
        "--region",
        "us-east-1",
        "--output",
        "json"
    ]

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        network_interfaces = json.loads(output)
        return network_interfaces
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None


def delete_security_groups(group_ids):

    deleted_groups = []
    failed_groups = []

    for group_id in group_ids:
        ec2 = boto3.client('ec2', region_name=group_id[1])
        try:
            response = ec2.delete_security_group(GroupId=group_id[0])
            deleted_groups.append(group_id[0])
            print(f"Security group {group_id[0]} in region {group_id[1]} deleted successfully.")
        except Exception as e:
            failed_groups.append(group_id[0])
            print(f"Failed to delete security group {group_id[0]} in region {group_id[1]}. Error: {str(e)}")

    print("\nDeletion summary:")
    print(f"  - Total security groups: {len(group_ids)}")
    print(f"  - Successfully deleted: {len(deleted_groups)}")
    print(f"  - Failed to delete: {len(failed_groups)}")

    if failed_groups:
        print("\nFailed security groups:")
        for group_id in failed_groups:
            print(f"  - {group_id}")


def get_security_group_rules(group_ids):
    ec2 = boto3.client('ec2')

    security_group_rules = {}

    for group_id in group_ids:
        try:
            inbound_rules = []
            outbound_rules = []

            # Retrieve inbound rules
            response = ec2.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [group_id]}])
            for rule in response['SecurityGroupRules']:
                if rule['IsEgress'] is False:
                    inbound_rule = {
                        'IpProtocol': rule['IpProtocol'],
                        'FromPort': rule.get('FromPort', '-'),
                        'ToPort': rule.get('ToPort', '-'),
                        'IpRanges': [ip_range['CidrIp'] for ip_range in rule.get('CidrIpv4Ranges', [])],
                        'UserIdGroupPairs': [group['GroupId'] for group in rule.get('ReferencedGroupInfo', {}).get('GroupId', [])]
                    }
                    inbound_rules.append(inbound_rule)

            # Retrieve outbound rules
            response = ec2.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [group_id]}, {'Name': 'egress', 'Values': ['true']}])
            for rule in response['SecurityGroupRules']:
                if rule['IsEgress'] is True:
                    outbound_rule = {
                        'IpProtocol': rule['IpProtocol'],
                        'FromPort': rule.get('FromPort', '-'),
                        'ToPort': rule.get('ToPort', '-'),
                        'IpRanges': [ip_range['CidrIp'] for ip_range in rule.get('CidrIpv4Ranges', [])],
                        'UserIdGroupPairs': [group['GroupId'] for group in rule.get('ReferencedGroupInfo', {}).get('GroupId', [])]
                    }
                    outbound_rules.append(outbound_rule)

            security_group_rules[group_id] = {
                'InboundRules': inbound_rules,
                'OutboundRules': outbound_rules
            }
        except Exception as e:
            print(f"Failed to retrieve rules for security group {group_id}. Error: {str(e)}")

    return security_group_rules


def main():
    parser = argparse.ArgumentParser(description='A script to clean up AWS security groups based on Security Hub severity level.')
    parser.add_argument('--level', type=str, default='info', help='The security level of the hub findings (CRITICAL, HIGH, etc)')
    parser.add_argument('--dryrun', action='store_true', help='Enable dryrun mode')

    args = parser.parse_args()

    level = args.level
    dryrun = args.dryrun

    print(f"Level: {level}")
    print(f"Dryrun: {dryrun}")

    unassociated_sg_group_ids = []
    unassociated_sg_group_names = []
    associated_sg_group_names = []
    sg_group_ids = []
    sg_group_names = []
    findings = get_findings(level)
    if findings:
        security_groups = parse_security_groups(findings)
        print("Security Groups:")
        for group in security_groups:
            print(f"Group Name: {group['GroupName']}, Group ID: {group['GroupId']}")
            
            network_interfaces = describe_network_interfaces(group['GroupId'])
            sg_group_ids.append([group['GroupId'], group['region']])
            sg_group_names.append(group['GroupName'])
            if network_interfaces and network_interfaces.get("NetworkInterfaces", []):
                print(f"Network Interfaces associated with Security Group {group['GroupId']}:")
                for interface in network_interfaces.get("NetworkInterfaces", []):
                    print(f"  - Network Interface ID: {interface['NetworkInterfaceId']}")
                    print(f"    Description: {interface.get('Description', 'N/A')}")
                    print(f"    Status: {interface['Status']}")
                    print(f"    Private IP Address: {interface['PrivateIpAddress']}")
                    print(f"    Instance ID: {interface.get('Attachment', {}).get('InstanceId', 'N/A')}")
                    print()
                    associated_sg_group_names.append(group['GroupName'])
            else:
                print(f"No network interfaces found for Security Group {group['GroupId']}")
                unassociated_sg_group_ids.append([group['GroupId'], group['region']])
                unassociated_sg_group_names.append(group['GroupName'])
            
            print()
    else:
        print("No critical findings found.")

    print("------")
    print("Unassociated SGs:")
    for sg_id, sg_region in unassociated_sg_group_ids:
        print(sg_id, sg_region)

    print("------")
    print("Associated SGs:")
    for sg_name in associated_sg_group_names:
        print(sg_name)

    print("------")
    print(f"The number of total security groups found for remediation is {len(sg_group_ids)}")
    
    print("------")
    print("SG IDs to remediate:")
    us_east_1_count = 0
    other_count = 0
    for sg_id, sg_region in sg_group_ids:
        print(sg_id, sg_region)
        if sg_region == 'us-east-1':
            us_east_1_count += 1
        else:
            other_count += 1

    print(f"us-east-1 count {us_east_1_count}")
    print(f"other count {other_count}")

    print("------")
    print("SG names to remediate:")
    for sg_name in sg_group_names:
        print(sg_name)

    if dryrun:
        print("This is a dry run, nothing will actually be deleted.")
    else:
        print("Deleting the SGs that need remediation")
        delete_security_groups(sg_group_ids)

if __name__ == "__main__":
    main()
