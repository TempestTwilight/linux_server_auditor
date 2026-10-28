# AWS Deployment Guide

This is your manual for the cloud pieces. Do them in order. Each step includes
the exact console or CLI action.

---

## Prerequisites

- An AWS account with MFA enabled on root.
- AWS CLI v2 installed locally (`aws --version`).
- This repo cloned on your Debian monitoring machine.

---

## Step 1 — Before you launch anything: set a billing alert

1. **AWS Console → Billing → Budgets → Create Budget**
2. Choose **Cost budget**, name it `auditor-limit`.
3. Set amount: **$10/month** (adjust to your comfort).
4. Alert threshold: 80% (i.e., $8).
5. Add your email as the alert recipient.
6. Create. **Do not skip this. Launch nothing until this exists.**

---

## Step 2 — Create the S3 telemetry bucket

**Region: `ap-southeast-2` (Mumbai) — use this everywhere below.**

### 2a. Create bucket

```bash
aws s3api create-bucket \
  --bucket fcc-s3-bucket-vd \
  --region ap-southeast-2 \
  --create-bucket-configuration LocationConstraint=ap-southeast-2
```

### 2b. Block all public access

```bash
aws s3api put-public-access-block \
  --bucket fcc-s3-bucket-vd \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 2c. Enable default encryption (SSE-S3)

```bash
aws s3api put-bucket-encryption \
  --bucket fcc-s3-bucket-vd \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
  }'
```

### 2d. Add TLS-only bucket policy

Save this as `/tmp/bucket-policy.json`, replacing `fcc-s3-bucket-vd`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::fcc-s3-bucket-vd",
        "arn:aws:s3:::fcc-s3-bucket-vd/*"
      ],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
```

Apply it:
```bash
aws s3api put-bucket-policy --bucket fcc-s3-bucket-vd --policy file:///tmp/bucket-policy.json
```

### 2e. Add a 14-day lifecycle rule

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket fcc-s3-bucket-vd \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "expire-telemetry",
      "Filter": {"Prefix": "telemetry/"},
      "Status": "Enabled",
      "Expiration": {"Days": 14}
    }]
  }'
```

---

## Step 3 — Create the EC2 IAM role (agent identity)

The EC2 instance uses an **instance profile** — no access keys stored on the server.

### 3a. Create the role

```bash
aws iam create-role \
  --role-name auditor-ec2-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'
```

### 3b. Create the policy — PutObject only, on the instance's own prefix

Save as `/tmp/ec2-policy.json`, replacing `fcc-s3-bucket-vd`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AgentPutOnly",
    "Effect": "Allow",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::fcc-s3-bucket-vd/telemetry/${aws:ec2InstanceID}/*"
  }]
}
```

```bash
aws iam create-policy \
  --policy-name auditor-ec2-put-policy \
  --policy-document file:///tmp/ec2-policy.json
```

> Note the `Policy.Arn` in the output — you'll need it next.

### 3c. Attach policy to role

```bash
aws iam attach-role-policy \
  --role-name auditor-ec2-role \
  --policy-arn arn:aws:iam::YOUR-ACCOUNT-ID:policy/auditor-ec2-put-policy
```

### 3d. Create instance profile and add role

```bash
aws iam create-instance-profile --instance-profile-name auditor-ec2-profile
aws iam add-role-to-instance-profile \
  --instance-profile-name auditor-ec2-profile \
  --role-name auditor-ec2-role
```

---

## Step 4 — Create the laptop IAM user (monitor identity)

### 4a. Create user

```bash
aws iam create-user --user-name auditor-reader
```

### 4b. Create the read-only policy

Save as `/tmp/reader-policy.json`, replacing `fcc-s3-bucket-vd`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListTelemetry",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::fcc-s3-bucket-vd",
      "Condition": {"StringLike": {"s3:prefix": "telemetry/*"}}
    },
    {
      "Sid": "GetTelemetry",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::fcc-s3-bucket-vd/telemetry/*"
    }
  ]
}
```

```bash
aws iam create-policy \
  --policy-name auditor-reader-policy \
  --policy-document file:///tmp/reader-policy.json

aws iam attach-user-policy \
  --user-name auditor-reader \
  --policy-arn arn:aws:iam::YOUR-ACCOUNT-ID:policy/auditor-reader-policy
```

### 4c. Create access key and save it

```bash
aws iam create-access-key --user-name auditor-reader
```

Save the `AccessKeyId` and `SecretAccessKey` output. Then on your **Debian laptop**:

```bash
mkdir -p ~/.aws
chmod 700 ~/.aws
cat >> ~/.aws/credentials << 'EOF'
[auditor-reader]
aws_access_key_id = PASTE_KEY_ID_HERE
aws_secret_access_key = PASTE_SECRET_HERE
region = ap-southeast-2
EOF
chmod 600 ~/.aws/credentials
```

Test it:
```bash
aws s3 ls s3://fcc-s3-bucket-vd/telemetry/ --profile auditor-reader
```
(Expect empty list — bucket is new.)

---

## Step 5 — Launch the EC2 instance

### 5a. Create a security group (outbound HTTPS only, no inbound SSH)

```bash
aws ec2 create-security-group \
  --group-name auditor-sg \
  --description "Linux Server Auditor — outbound only" \
  --region ap-southeast-2
```

Note the `GroupId` (e.g. `sg-xxxxxxxxxxxxxxxxx`).

By default a new security group has one outbound rule: allow all. Delete it and add HTTPS-only:

```bash
# Remove default allow-all outbound
aws ec2 revoke-security-group-egress \
  --group-id sg-0dde1887f2fe2687b \
  --protocol -1 --port -1 --cidr 0.0.0.0/0 \
  --region ap-southeast-2

# Allow HTTPS outbound only (for S3 and IMDS)
aws ec2 authorize-security-group-egress \
  --group-id sg-0dde1887f2fe2687b \
  --protocol tcp --port 443 --cidr 0.0.0.0/0 \
  --region ap-southeast-2
```

> **No inbound rules.** Use AWS Systems Manager Session Manager for shell access
> (no SSH port needed). If you must SSH, add `--cidr YOUR.HOME.IP/32 --port 22`
> inbound only; never `0.0.0.0/0`.

### 5b. Enable SSM access (to use Session Manager instead of SSH)

Add the managed policy to your EC2 role:
```bash
aws iam attach-role-policy \
  --role-name auditor-ec2-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
```

### 5c. Find the latest Ubuntu 22.04 LTS AMI

```bash
aws ec2 describe-images \
  --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
            "Name=state,Values=available" \
  --query "sort_by(Images, &CreationDate)[-1].ImageId" \
  --output text \
  --region ap-southeast-2
```

Note the AMI ID (e.g. `ami-xxxxxxxxxxxxxxxxx`).

### 5d. Launch instance

```bash
aws ec2 run-instances \
  --image-id ami-0af9110f0ec0820e2 \
  --instance-type t3.micro \
  --iam-instance-profile Name=auditor-ec2-profile \
  --security-group-ids sg-0dde1887f2fe2687b \
  --count 1 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=linux-server-auditor}]' \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --region ap-southeast-2 \
  --no-cli-pager
```

Note the `InstanceId` (e.g. `i-xxxxxxxxxxxxxxxxx`).

`--metadata-options HttpTokens=required` enforces IMDSv2 (the plan's requirement).

### 5e. Wait for instance to be running

```bash
aws ec2 wait instance-running --instance-ids i-0e1df82e71bf711d0 --region ap-southeast-2
```

---

## Step 6 — Deploy the agent to EC2

### 6a. Connect via Session Manager

```bash
aws ssm start-session --target i-0e1df82e71bf711d0 --region ap-southeast-2
```

(Requires `session-manager-plugin` installed locally and the EC2 instance to have been running for ~2 minutes for SSM agent to register.)

### 6b. Inside the session — clone and run setup

```bash
# As ubuntu user inside the session:
sudo apt-get update -qq && sudo apt-get install -y git
git clone https://github.com/YOUR-USERNAME/linux_server_auditor.git /tmp/linux_server_auditor
cd /tmp/linux_server_auditor
sudo bash scripts/setup_ec2.sh fcc-s3-bucket-vd
```

### 6c. Verify the agent is running and uploading

```bash
sudo journalctl -u linux-server-auditor -f
```

You should see log lines like:
```
agent start: instance=i-xxxx run=...
batch ready: batch_1234567890.jsonl
```

Wait ~30 seconds, then check S3 from your **laptop**:
```bash
aws s3 ls s3://fcc-s3-bucket-vd/telemetry/i-0e1df82e71bf711d0/ --profile auditor-reader
```

---

## Step 7 — Update config/settings.yaml in the repo

Open `config/settings.yaml` and set:
```yaml
s3:
  bucket: fcc-s3-bucket-vd
agent:
  instance_id: i-0e1df82e71bf711d0
```

Commit this (the bucket name is not a secret; the access keys are never committed).

---

## Teardown (when done with the project)

```bash
# Stop the instance (keeps EBS, stops compute charges)
aws ec2 stop-instances --instance-ids i-0e1df82e71bf711d0 --region ap-southeast-2

# To terminate (deletes EBS too):
aws ec2 terminate-instances --instance-ids i-0e1df82e71bf711d0 --region ap-southeast-2

# Delete S3 contents and bucket
aws s3 rm s3://fcc-s3-bucket-vd --recursive
aws s3api delete-bucket --bucket fcc-s3-bucket-vd --region ap-southeast-2

# Deactivate and delete the reader key
aws iam delete-access-key --user-name auditor-reader --access-key-id PASTE_KEY_ID_HERE
```

Rotate or delete the IAM user and role when done.

---

## Cost estimate (ap-southeast-2, Oct 2026)

| Resource | Estimate |
|---|---|
| t3.micro EC2 (24h/day) | ~$0.011/hr → ~$8/month |
| EBS gp3 8 GB | ~$0.70/month |
| S3 (14-day retention, ~1 MB/batch) | < $0.01/month |
| S3 requests | < $0.01/month |
| Public IPv4 address | $0.005/hr → ~$3.60/month |
| **Total** | **~$12/month** |

Use a t3.micro or t4g.micro (ARM). Stop the instance when not actively collecting.
