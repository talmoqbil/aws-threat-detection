import json
import boto3
import gzip
import io

sns_client = boto3.client('sns')
s3_client = boto3.client('s3')

SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:699222026265:SecurityAlerts'

def lambda_handler(event, context):
    print("Received event:", json.dumps(event, indent=2))

    if "Records" not in event:
        print("No records found in event")
        return {"status": "No records"}

    for record in event["Records"]:
        s3_bucket = record["s3"]["bucket"]["name"]
        s3_key = record["s3"]["object"]["key"]

        try:
            # fetch cloudTrail log file from S3
            print(f"Attempting to read file: s3://{s3_bucket}/{s3_key}")
            response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
            body = response["Body"].read()

            # Detect if the file is compressed (will be fixed to support different types)
            if s3_key.endswith(".gz"):
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as f:
                    log_data = json.loads(f.read().decode("utf-8"))
            else:
                log_data = json.loads(body.decode("utf-8"))

            # Ensure log data contains "Records"
            if "Records" not in log_data:
                print("No records found in CloudTrail log file:", s3_key)
                return {"status": "No records"}

            # Scan logs for anything suspicious activity
            for log_record in log_data["Records"]:
                event_name = log_record.get("eventName", "")
                user_identity = log_record.get("userIdentity", {}).get("arn", "Unknown")

                if event_name in ["DeleteBucketPolicy", "CreateUser", "AttachRolePolicy"]:
                    alert_message = f"⚠️ Suspicious activity detected: {event_name} by {user_identity}"
                    print(alert_message)

                    # Send SNS 
                    sns_client.publish(
                        TopicArn=SNS_TOPIC_ARN,
                        Message=alert_message,
                        Subject="AWS Security Alert"
                    )

        except boto3.exceptions.Boto3Error as e:
            print("AWS Boto3 Error:", str(e))
            return {"status": "Error", "message": "Boto3-related issue"}

        except json.JSONDecodeError as e:
            print("JSON Decode Error:", str(e))
            return {"status": "Error", "message": "Invalid JSON format in log file"}

        except Exception as e:
            print(f"Unexpected error processing log file {s3_key} from {s3_bucket}: {str(e)}")
            return {"status": "Error", "message": str(e)}

    return {"status": "Success"}