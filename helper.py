import os
import boto3
import datetime
import jwt

jwt_secret_key = os.environ.get('JWT_SECRET_KEY')
AWS_BUCKET = os.environ.get('AWS_BUCKET')
AWS_REGION = os.environ.get('AWS_REGION')

S3 = boto3.client(
    "s3",
    os.environ.get('AWS_REGION'),
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
)

def upload_image(image_file, aws_key):

    S3.upload_fileobj(
        image_file,
        AWS_BUCKET,
        aws_key,
        ExtraArgs={
            "ACL": "public-read",
            "ContentType": image_file.content_type
            }
    )

    return True

def generate_image_url(aws_key):
    return f'https://{AWS_BUCKET}.s3.amazonaws.com/{aws_key}'

def create_token(user):

    username = user.username
    user_id = user.id
    is_admin = user.is_admin

    now = datetime.datetime.now(datetime.UTC)
    exp_time = now + datetime.timedelta(hours=2)  # Token expires in 2 hours


    payload = {
        'username': username,
        'user_id' : user_id,
        'is_admin': is_admin,
        'iat': now,
        'exp': exp_time,
    }

    token = jwt.encode(
        payload,
        jwt_secret_key,
        algorithm='HS256'
    )

    return token