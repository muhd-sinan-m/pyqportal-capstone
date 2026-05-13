import boto3
from botocore.exceptions import ClientError
import uuid
from flask import current_app

def get_s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id     = current_app.config["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key = current_app.config["AWS_SECRET_ACCESS_KEY"],
        region_name           = current_app.config["AWS_REGION"]
    )

def upload_file_to_s3(file_obj, subject_id, year):
    """Upload a PDF to S3 and return (public_url, s3_key)"""
    s3      = get_s3_client()
    bucket  = current_app.config["S3_BUCKET_NAME"]
    region  = current_app.config["AWS_REGION"]

    # Unique key — same structure as before
    s3_key  = f"papers/{subject_id}/{year}/{uuid.uuid4()}.pdf"

    s3.upload_fileobj(
        file_obj,
        bucket,
        s3_key,
        ExtraArgs={
            "ContentType": "application/pdf",
            "ACL":         "public-read"
        }
    )

    # Public URL format for S3
    public_url = f"https://{bucket}.s3.{region}.amazonaws.com/{s3_key}"

    return public_url, s3_key

def delete_file_from_s3(s3_key):
    """Delete a file from S3 by its key"""
    if not s3_key:
        return
    try:
        s3     = get_s3_client()
        bucket = current_app.config["S3_BUCKET_NAME"]
        s3.delete_object(Bucket=bucket, Key=s3_key)
    except ClientError as e:
        print(f"S3 delete error: {e}")