import boto3
from botocore.exceptions import ClientError
import csv
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ROOT_USER = "<root_account>"
PASSWORD_LAST_USED = "password_last_used"
MFA_ACTIVE = "mfa_active"
ACCESS_KEY_ONE_ACTIVE = "access_key_1_active"
ACCESS_KEY_TWO_ACTIVE = "access_key_2_active"
ARN="arn:aws:sns:us-east-1:657664787491:CIS"

class CISAuditor:
    def __init__(self, credential_report):
        self.credential_report = credential_report

    def get_root_user_last_activity(self):
        return self.credential_report[ROOT_USER][PASSWORD_LAST_USED]

    def get_users_with_unactive_mfa(self):
        return [user for user, user_data in self.credential_report.items() if user_data[MFA_ACTIVE] == "false"]

    def is_access_key_attached_to_root_account(self):
        return self.credential_report[ROOT_USER][ACCESS_KEY_ONE_ACTIVE] == "true" or self.credential_report[ROOT_USER][ACCESS_KEY_TWO_ACTIVE] == "true"

def get_assumed_role_credentials():
    sts_connection = boto3.client('sts')
    assumed_role_object = sts_connection.assume_role(
        RoleArn="arn:aws:iam::657664787491:role/IAM-Auditor-role",
        RoleSessionName="audit_session"
    )
    return assumed_role_object["Credentials"]

def get_credential_report(credentials):
    iam=boto3.client(
        'iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    report_complete = False
    try:
        while not report_complete:
            response = iam.generate_credential_report()
            logger.info("Generating credentials report for your account.")
            report_complete = response['State'] == 'COMPLETE'
            if not report_complete:
                sleep(1)

    except ClientError:
        logger.exception("Couldn't generate a credentials report for your account.")
        raise

    try:
        response = iam.get_credential_report()
        logger.info("Getting credentials report for your account.")
    except ClientError:
        logger.exception("Couldn't get a credentials report for your account.")
        raise

    dict_reader = csv.DictReader(response['Content'].decode("utf-8").split("\n"))

    credential_report = {}
    for row in dict_reader:
        credential_report[row["user"]] = row

    return credential_report

def send_cis_eport_to_admin(credential_report):
    client = boto3.client('sns')
    auditor = CISAuditor(credential_report)
    message = {
        "root_user_last_activity": auditor.get_root_user_last_activity(),
        "users_with_unactive_mfa": auditor.get_users_with_unactive_mfa(),
        "access_key_attached_to_root_account": auditor.is_access_key_attached_to_root_account()
    }

    try:
        response = client.publish(
            TargetArn=ARN,
            Message=json.dumps({'default': json.dumps(message)}),
            MessageStructure='json'
        )
    except ClientError:
        logger.exception("Couldn't publish report to your account.")
        raise

def lambda_handler(event, context):
    credentials = get_assumed_role_credentials()
    credential_report = get_credential_report(credentials)

    send_cis_eport_to_admin(credential_report)

    return {
        'statusCode': 200,
        'body': "Message sent successfully."
    }
