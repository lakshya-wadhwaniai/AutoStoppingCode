"""
This module is used for autostopping resources like RDS,EC@,IAM if not
provided proper tags of Project and Email
"""
import json
import logging
import requests
import traceback
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_secret(secret_name, region_name):
    ''' Function to get the access credentials given the secretname. '''
    session = boto3.session.Session()
    secret_client = session.client(service_name='secretsmanager', region_name=region_name)
    get_secret_value_response = secret_client.get_secret_value(SecretId=secret_name)
    return get_secret_value_response['SecretString']
def find_username(event):
    """thie method find IAM Username
    event->dictionary, the event passsed via cloudtrial
    returns rhe username
    """
    user_name=' '
    try:
        if 'userIdentity' in event['detail']:
            if event['detail']['userIdentity']['type'] == 'AssumedRole':
                user_name = str('UserName: ' + event['detail']['userIdentity']['principalId']\
                    .split(':')[1] + ', Role: ' + event['detail']['userIdentity']\
                        ['sessionContext']['sessionIssuer']['userName'] + ' (role)')
            elif event['detail']['userIdentity']['type'] == 'IAMUser':
                user_name = event['detail']['userIdentity']['userName']
            elif event['detail']['userIdentity']['type'] == 'Root':
                user_name = 'root'
            else:
                logging.info('Could not determine username (unknown iam userIdentity) ')
                user_name = ''
        else:
            logging.info('Could not determine username (no userIdentity data in cloudtrail')
            user_name = ''
    except KeyError as ex_cep:
        logging.info('could not find username, exception: %s' , str(ex_cep))
        user_name = ''
    return user_name

def send_mail(url, file_path, sender_email_id, recipient_email_id, email_subject, body_text, body_html,
            attachment_name, TOKEN):
    """
    Send email to recipients. Sends one mail to all recipients.
    url: The email service url
    sender_email_id: Email address of the sender
    recipient_email_id: List of email addresses to which the email is to be sent
    email_subject: Title of the email or Subject of the email
    body_text: Email content in text format
    body_html: Email content in HTML format
    file_path: Attachment path
    attachment_name: List of attachements name to the mail.
    The elements of the list are paths to the files that are to be attached.
    Return A dictionary with Source, Destination and RawMessage
    """
    if file_path:
        files = {"email_attachment": open(file_path, 'rb')}
    headers = {"TOKEN": TOKEN}
    data = {"sender_email_id": sender_email_id, "recipient_email_id": recipient_email_id,
            "email_subject": email_subject,
            "body_text": body_text,
            "body_html": body_html,
            "attachment_name": attachment_name,
            "persist_email": False}
    r = requests.post(url, data=data, files=files if file_path else None, headers=headers)
    return json.loads(r.text)["email_status"]

def check_and_get_email(my_list,tag):
    """ This function checks whether resource has Email tag or not and hence return email tag value
    my_list->List containing all tags of particular resource
    tag->string, tag to check
    returns value of tag it has that particular tag and false otherwise
    """
    logging.info('Looking for tag [' + tag + '] in list %s ',  json.dumps(my_list))
    for i in my_list:
        if i['Key'] == tag:
            evalue=i['Value']
            return evalue
    return False

def check_for_tag(my_list,tag):
    """
    This function checks whether resource has tags or not
    my_list->List containing all tags of particular resource
    tag->string, tag to check
    returns True if it has tags and false otherwise
    """
    logging.info('Looking for tag [' + tag + '] in list %s' , json.dumps(my_list))
    for i in my_list:
        print(type(i['Key']))
        print(type(tag))
        if i['Key'] == tag:
            return True
    return False

def ec2_tag(event,aws_region,email_sender,user_name,value,account_Id):
    """Helper function for ec2
    event->dictionary, the event passsed via cloudtrial,
    aws_region->string, Region where the resource is being created,
    """
    try:
        instance_id = [x['instanceId'] for x in event['detail']\
            ['responseElements']['instancesSet']['items']]
    except KeyError:
        instance_id = []
    client = boto3.client('ec2', region_name=aws_region)
    if instance_id:
        email="Email"
        project="Project"
        URL=value['URL']
        TOKEN=value['TOKEN']
        for instance in instance_id:
            try:
                waiter = client.get_waiter('instance_running')
                waiter.wait(
                InstanceIds=[instance,],
                WaiterConfig={
                    'Delay': 30,
                    'MaxAttempts': 150
                }
                )
            except:
                logging.info("wait condition failure")
            # Let's tag the instance
            instance_api = client.describe_instances(InstanceIds=[instance])
            # Get all ec2 instance tags
            if 'Tags' in instance_api['Reservations'][0]['Instances'][0]:
                instance_tags = instance_api['Reservations'][0]['Instances'][0]['Tags']
            else:
                instance_tags = []
            # Check if 'Iam user' tag exist in instance tags
            if instance_tags:
                if check_for_tag(instance_tags,email) and  check_for_tag(instance_tags,project):
                    logging.info('Project and Email tag already exist for ec2 instance, Hence Stopping %s',instance)
                    return
                else:
                    evalue=check_and_get_email(instance_tags,'Email')
                    if evalue is None or evalue is False:
                        iam_client = boto3.client('iam')
                        tags = iam_client.list_user_tags(UserName =user_name)
                        evalue=check_and_get_email(tags['Tags'],'Email')
                    if evalue is not None:
                        file_path = ""
                        sender_email_id = email_sender
                        recipient_email_id = evalue
                        email_subject = 'EC2 Instance stopped: ' + instance
                        body_text = ""
                        body_html = '<html> <head></head> <body> Hi ' + user_name +' <p>You are receiving this notification as your newly created AWS instance  '+ instance + ' present in account : ' +account_Id + ' and region : '+aws_region + ' has been automatically stopped because of non-compliant tagging. To start the instance, please add the missing tags and then start it.</p><p>You can refer to the tagging guidelines on the wiki link here:  https://wadhwaniai.atlassian.net/wiki/spaces/REG/pages/1721794568/AWS+Auto-tagging+Guidelines</p><p>Note: This is an auto-generated email. Please do not reply to it, as the mailbox is not monitored.</p><p> Thanks,</p><p>Your AWS Admin</p> </body> </html>'
                        attachment_name = "No attachment"
                        logging.info(send_mail(URL, file_path, sender_email_id, recipient_email_id, email_subject, body_text, body_html,
                                        attachment_name, TOKEN))
                    logging.info('Ec2 instance %s not tagged properly',instance)
                    client.stop_instances(InstanceIds=[instance])
            else:
                iam_client = boto3.client('iam')
                tags = iam_client.list_user_tags(UserName =user_name)
                evalue=check_and_get_email(tags['Tags'],'Email')
                if evalue is not None:
                    file_path = ""
                    sender_email_id = email_sender
                    recipient_email_id = evalue
                    email_subject = 'EC2 Instance stopped: ' + instance
                    body_text = ""
                    body_html = '<html> <head></head> <body> Hi ' + user_name +' <p>You are receiving this notification as your newly created AWS instance  '+ instance + ' present in account : ' +account_Id + ' and region : '+ aws_region + ' has been automatically stopped because of non-compliant tagging. To start the instance, please add the missing tags and then start it.</p><p>You can refer to the tagging guidelines on the wiki link here:  https://wadhwaniai.atlassian.net/wiki/spaces/REG/pages/1721794568/AWS+Auto-tagging+Guidelines</p><p>Note: This is an auto-generated email. Please do not reply to it, as the mailbox is not monitored.</p><p> Thanks,</p><p>Your AWS Admin</p> </body> </html>'
                    attachment_name = "No attachment"
                    logging.info(send_mail(URL, file_path, sender_email_id, recipient_email_id, email_subject, body_text, body_html,
                                    attachment_name, TOKEN))
                client.stop_instances(InstanceIds=[instance])
                logging.info('Instance %s has no tags, \
                    let\'sstop ' ,instance)

def rds_tag(event,aws_region,email_sender,user_name,value,account_Id):
    """Helper function for rds
    event->dictionary, the event passsed via cloudtrial,
    aws_region->string, Region where the resource is being created,
    """
    rds_client = boto3.client('rds' ,region_name=aws_region)
    rds_instance = event['detail']['responseElements']['dBInstanceArn']
    rds_name = event['detail']['requestParameters']['dBInstanceIdentifier']
    rds_tags = rds_client.list_tags_for_resource(ResourceName=rds_instance)
    email="Email"
    project="Project"
    URL=value['URL']
    TOKEN=value['TOKEN']
    evalue=check_and_get_email(rds_tags['TagList'],'Email')
    if evalue is None or evalue is False:
        iam_client = boto3.client('iam')
        tags = iam_client.list_user_tags(UserName =user_name)
        evalue=check_and_get_email(tags['Tags'],'Email')
    logging.error(evalue)
    logging.error("inside")
    if check_for_tag(rds_tags['TagList'],email) and  check_for_tag(rds_tags['TagList'],project):
        logging.error('Project and Email tag already exist for rds %s',rds_instance)
        return
    if evalue is not None:
        file_path = ""
        sender_email_id = email_sender
        recipient_email_id = evalue
        email_subject = 'RDS Instance stopped: ' + rds_name
        body_text = ""
        body_html = '<html> <head></head> <body> Hi ' + user_name +' <p>You are receiving this notification as your newly created AWS RDS Instance  '+ rds_name + ' present in account : ' +account_Id +' and region: '+aws_region +' has been automatically stopped because of non-compliant tagging. To start the instance, please add the missing tags and then start it.</p><p>You can refer to the tagging guidelines on the wiki link here:  https://wadhwaniai.atlassian.net/wiki/spaces/REG/pages/1721794568/AWS+Auto-tagging+Guidelines</p><p>Note: This is an auto-generated email. Please do not reply to it, as the mailbox is not monitored.</p><p> Thanks,</p><p>Your AWS Admin</p> </body> </html>'
        attachment_name = "No attachment"
        logging.error(send_mail(URL, file_path, sender_email_id, recipient_email_id, email_subject, body_text, body_html,
                        attachment_name, TOKEN))
    waiter = rds_client.get_waiter('db_instance_available')
    waiter.wait(DBInstanceIdentifier=rds_name)
    
    try:
        logging.error("try")
        logging.info("else")
        logging.error('Rds %s not tagged properly Hence Stopping',rds_instance)
        rds_client.stop_db_instance(DBInstanceIdentifier=rds_name)
    except ClientError as error:
        logging.info('Unexpected error occurred \
            hence cleaning up %s',error)
        traceback.print_exc()

def iam_tag(event,policy_arn,email_sender,value,infra_mail_id,account_Id,aws_region):
    """Helper function for iam
    event->dictionary, the event passsed via cloudtrial
    """
    user_name=event['detail']['requestParameters']['userName']
    iam_client = boto3.client('iam')
    tags = iam_client.list_user_tags(UserName = user_name)
    email="Email"
    if check_for_tag(tags['Tags'],email):
        return
    try:
        URL=value['URL']
        TOKEN=value['TOKEN']
        file_path = ""
        sender_email_id = email_sender
        recipient_email_id = infra_mail_id
        email_subject = 'Non-compliant IAM tag for user: ' + user_name
        body_text = ""
        body_html = '<html> <head></head> <body> Hi Admins, <p>You are receiving this notification as the IAM User: '+ user_name + 'present in account : '+account_Id+ ' and region : '+aws_region+ ' is missing the Email tag. Due to tagging non-compliance, the newly created IAM User has been denied ALL permission. To resolve this issue, please add the Email tag to the user IAM user id.</p><p> Thanks,</p><p>Your AWS Admin</p> </body> </html>'
        attachment_name = "No attachment"
        logging.info(send_mail(URL, file_path, sender_email_id, recipient_email_id, email_subject, body_text, body_html,
                        attachment_name, TOKEN))
        logging.info("mail sent")
        iam_client.attach_user_policy(
            UserName=user_name,
            PolicyArn=policy_arn
        )
        return
    except ClientError as error:
        logging.info('Unexpected error occurred while attaching policy...\
            hence cleaning up %s',error)
        traceback.print_exc()
        return

def lambda_handler(event, _context):
    """
    This method stops resources if not found with proper tags for RDS,EC2,IAM
    """
    if 'detail' in event:
        user_name=find_username(event)
        account_Id = event['detail']['userIdentity']['accountId']
        with open('config.json') as file:
            data = json.load(file)
        policy_arn=data['policy_arn']
        email_sender=data['email_sender']
        secret_name=data['secret_name']
        secret_region=data['secret_region']
        infra_mail_id=data['infra_mail_id']
        aws_region = event['detail']['awsRegion']
        value=json.loads(get_secret(secret_name,secret_region))
        if event['source'] == "aws.ec2":
            ec2_tag(event,aws_region,email_sender,user_name,value,account_Id)
        elif event['source'] == "aws.rds":
            rds_tag(event,aws_region,email_sender,user_name,value,account_Id)
        elif event['source'] == "aws.iam":
            iam_tag(event,policy_arn,email_sender,value,infra_mail_id,account_Id,aws_region)