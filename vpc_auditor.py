import boto3

print("=" * 55)
print("   VPC SECURITY AUDITOR by papa_jay")
print("=" * 55)

ec2 = boto3.client('ec2')
issues = 0

vpcs = ec2.describe_vpcs()['Vpcs']
print(f"\nFound {len(vpcs)} VPC(s)\n")

for vpc in vpcs:
    vpc_id = vpc['VpcId']
    is_default = vpc['IsDefault']
    name = next((t['Value'] for t in vpc.get('Tags',[]) if t['Key']=='Name'), 'Unnamed')
    print(f"VPC: {name} ({vpc_id})")
    if is_default:
        print(f"  WARNING: Default VPC — delete it!")
        issues += 1
    else:
        print(f"  OK: Custom VPC")
    logs = ec2.describe_flow_logs(
        Filters=[{'Name':'resource-id','Values':[vpc_id]}]
    )
    if not logs['FlowLogs']:
        print(f"  WARNING: No Flow Logs!")
        issues += 1
    else:
        print(f"  OK: Flow Logs enabled")
    print("")

sgs = ec2.describe_security_groups()['SecurityGroups']
print(f"Scanning {len(sgs)} Security Groups...\n")
for sg in sgs:
    for rule in sg['IpPermissions']:
        for ip in rule.get('IpRanges',[]):
            if ip.get('CidrIp') == '0.0.0.0/0':
                port = rule.get('FromPort','ALL')
                if port != 443:
                    print(f"  WARNING: {sg['GroupName']} allows ALL traffic on port {port}!")
                    issues += 1

print("=" * 55)
print(f"   SCAN COMPLETE - {issues} issues found")
print("=" * 55)
