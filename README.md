# AWS Cloud Canary — Credential Misuse Detection

A serverless honeypot that detects and logs unauthorized AWS access key usage in real time.

## Overview
This project uses native AWS services to detect credential misuse:
**CloudTrail → S3 → Lambda → DynamoDB** (optional SNS for alerts).

## Why I built it
To simulate credential compromise, detect unauthorized key usage quickly, and record forensic evidence (eventName, IP, region, timestamp, userAgent) for investigation.


## Components & roles
- **CloudTrail** — captures all API calls.
- **S3** — stores CloudTrail delivery (`.json.gz`).
- **Lambda** — parses delivered logs, filters for canary key, writes structured records to DynamoDB.
- **DynamoDB** — stores parsed events for quick forensic lookup.
- **SNS (optional)** — sends immediate alerts for high-severity events.

## Example

A simulated attacker runs an AWS CLI command using the canary credentials:

```bash
aws sts get-caller-identity --profile canary
```

Within minutes, CloudTrail logs the API call → S3 stores the log → Lambda parses it → DynamoDB records the event.

The DynamoDB table below shows the captured record with event details such as:

eventName: GetCallerIdentity
eventSource: sts.amazonaws.com
sourceIPAddress: (attacker’s IP)
eventTime: (timestamp of call)


