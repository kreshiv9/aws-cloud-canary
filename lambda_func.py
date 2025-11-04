import boto3
import gzip
import json
import io
import os

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('from-lambda--final-events')

CANARY_KEY_ID = os.environ.get("CANARY_KEY_ID", "").strip()

def lambda_handler(event, context):
    if 'Records' not in event:
        print("No Records in event")
        return {'status': 'no_records'}

    for record in event['Records']:
        s3_info = record.get('s3')
        if not s3_info:
            continue

        bucket = s3_info['bucket']['name']
        key = s3_info['object']['key']
        print(f"Processing s3://{bucket}/{key}")

        try:
            # Read and decompress CloudTrail file
            response = s3.get_object(Bucket=bucket, Key=key)
            body = response['Body'].read()
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
                data = json.loads(gz.read().decode('utf-8'))

            # Loop through each CloudTrail event
            for evt in data.get('Records', []):
                access_key = evt.get('userIdentity', {}).get('accessKeyId', '')
                user_name = evt.get('userIdentity', {}).get('userName', '')

                # ✅ FILTER: only store if matches canary
                if access_key == CANARY_KEY_ID or user_name == "canary-user":
                    item = {
                        'eventID': evt.get('eventID', 'none'),
                        'eventTime': evt.get('eventTime', 'unknown'),
                        'eventName': evt.get('eventName', 'unknown'),
                        'userName': user_name or 'unknown',
                        'sourceIPAddress': evt.get('sourceIPAddress', 'unknown'),
                        'awsRegion': evt.get('awsRegion', 'unknown'),
                        'eventSource': evt.get('eventSource', 'unknown'),
                        'accessKeyId': access_key
                    }
                    table.put_item(Item=item)
                    print(f"✅ Logged canary event: {item['eventName']} at {item['eventTime']}")
                else:
                    # Skip irrelevant event
                    continue

        except Exception as e:
            print(f"Error processing {bucket}/{key}: {e}")
            continue

    return {'status': 'done'}
