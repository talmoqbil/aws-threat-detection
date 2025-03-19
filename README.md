# Improved: AWS Serverless Threat Detection System

##  Project Overview
This project sets up an AWS Serverless Threat Detection System using:

- AWS Lambda: Analyzes CloudTrail logs for suspicious activities.
- AWS CloudTrail: Logs AWS API activity.
- Amazon SNS: Sends security alerts via email/SMS.

The system automates security monitoring by detecting:

- Unauthorized IAM role modifications  
- Public S3 bucket policy changes  
- Other critical AWS security events  

##  Tech Stack
- AWS CloudTrail (Audit logs)
- AWS Lambda (Serverless computing)
- AWS SNS (Real-time alerts)
- Amazon S3 (CloudTrail log storage)
- Python (boto3 SDK) (AWS automation)

##  Architecture Diagram
- Will be added in due time.

##  How It Works
- CloudTrail logs AWS API calls to an S3 bucket.  
- S3 event notifications trigger Lambda when a new log is added.  
- Lambda scans the logs for suspicious activities (e.g., `CreateUser`).  
- If a threat is detected, SNS sends a security alert. 

## IAM Permissions
The Lambda function **requires**:

- S3 Read Access
- SNS Publish Access
- CloudWatch Logging

##  Deployment Steps

### 1.  Enable CloudTrail
1. Navigate to AWS CloudTrail → Create a new trail 
2. Store logs in Amazon S3 (private bucket)
3. Enable multi-region logging
4. Enable CloudWatch Logs integration  

### 2.  Deploy AWS Lambda Function
1. Go to AWS Lambda → **Create Function
2. Select Python 3.x
3. Attach the required IAM policies:
   - `AWSLambdaBasicExecutionRole`
   - `CloudWatchLogsFullAccess`
   - `S3 Read-Only Access`
4. Deploy `lambda_function.py` (code in `/lambda` folder)
5. Configure an S3 Event Trigger for CloudTrail logs.

### 3.  Set Up SNS Notifications
1. Create an Amazon SNS Topic (`SecurityAlerts`)
2. Subscribe with your email/SMS
3. Update Lambda to send alerts to SNS.

### 4. Test the System
- Create an IAM user with Admin Access → Should trigger an alert  
- Delete an S3 bucket policy → Should trigger an alert  


## Future Enhancements
- Add AWS Security Hub integration for advanced threat intelligence.  
- Store logs in **Amazon S3 + Athena for security analytics.  
- Implement automated remediation via AWS Lambda.  

---
## Demo
- Contact me at tariqalmegbel@gmail.com for a demo video as requirements may change and videos may be outdated.

## References
- [AWS CloudTrail Docs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-introduction.html)
- [AWS Lambda Docs](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html)
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
