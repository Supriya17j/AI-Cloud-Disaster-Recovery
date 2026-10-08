import boto3
import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")

BRANCHES = ['mumbai', 'delhi', 'bangalore', 'chennai', 'hyderabad']

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION
    )

def upload_to_s3(branch):
    s3 = get_s3_client()
    bucket_name = f"disaster-recovery-{branch}-255274109745-ap-south-1-an"
    branch_folder = f"branch_{branch}"
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    uploaded = []

    try:
        for filename in os.listdir(branch_folder):
            filepath = os.path.join(branch_folder, filename)
            if os.path.isfile(filepath):
                s3_key = f"backup_{timestamp}/{filename}"
                s3.upload_file(filepath, bucket_name, s3_key)
                uploaded.append(s3_key)
                print(f"   ✓ Uploaded {filename} → s3://{bucket_name}/{s3_key}")

        print(f"   ✅ Backup complete for {branch.upper()} — {len(uploaded)} files uploaded")
        return True

    except Exception as e:
        print(f"   ✗ Backup failed for {branch}: {e}")
        return False

def get_backup_history(branch):
    s3 = get_s3_client()
    bucket_name = f"disaster-recovery-{branch}"

    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' not in response:
            return []

        backups = []
        for obj in response['Contents']:
            backups.append({
                "file": obj['Key'],
                "size": obj['Size'],
                "last_modified": obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S')
            })
        return backups

    except Exception as e:
        print(f"   ✗ Failed to fetch history for {branch}: {e}")
        return []

if __name__ == "__main__":
    print("Testing S3 backup for all branches...\n")
    for branch in BRANCHES:
        print(f"📍 Backing up {branch.upper()}...")
        upload_to_s3(branch)
        print()