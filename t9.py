import boto3
from botocore.exceptions import ClientError
import csv
import json
import logging
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_assumed_role_credentials():
    sts_connection = boto3.client('sts')
    assumed_role_object = sts_connection.assume_role(
        RoleArn="arn:aws:iam::657664787491:role/IAM-Auditor-role",
        RoleSessionName="audit_session"
    )
    return assumed_role_object["Credentials"]

def get_credential_report(credentials):
    iam=boto3.client('iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'])

    report_complete = False
    try:
        while not report_complete:
            response = iam.generate_credential_report()
            logger.info("Generating credentials report for your account. ")
            report_complete = response['State'] == 'COMPLETE'
            if not report_complete:
                time.sleep(1)

    except ClientError:
        logger.exception("Couldn't generate a credentials report for your account.")
        raise

    try:
        response = iam.get_credential_report()
        logger.info("Getting credentials report for your account. ")
    except ClientError:
        logger.exception("Couldn't get a credentials report for your account.")
        raise
    else:
        return response['Content'].decode("utf-8")


def lambda_handler(event, context):
    credentials = get_assumed_role_credentials()
    credential_report = get_credential_report(credentials)
    credential_report_list = list(csv.DictReader(credential_report.split("\n")))

    return {
        'statusCode': 200,
        'body': credential_report_list
    }
