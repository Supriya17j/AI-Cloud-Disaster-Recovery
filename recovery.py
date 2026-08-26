import boto3
import os
from dotenv import load_dotenv

load_dotenv()

BUCKET_SUFFIX = "255274109745-ap-south-1-an"

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION")
    )

def list_backups(branch):
    s3 = get_s3_client()
    bucket_name = f"disaster-recovery-{branch}-{BUCKET_SUFFIX}"

    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' not in response:
            print(f"   No backups found for {branch.upper()}")
            return []

        # Group files by backup timestamp folder
        backups = {}
        for obj in response['Contents']:
            folder = obj['Key'].split('/')[0]
            if folder not in backups:
                backups[folder] = []
            backups[folder].append(obj['Key'])

        print(f"\n📦 Backups available for {branch.upper()}:")
        for folder, files in sorted(backups.items(), reverse=True):
            print(f"   → {folder} ({len(files)} files)")

        return list(backups.keys())

    except Exception as e:
        print(f"   ✗ Failed to list backups for {branch}: {e}")
        return []

def restore_backup(branch, backup_timestamp):
    s3 = get_s3_client()
    bucket_name = f"disaster-recovery-{branch}-{BUCKET_SUFFIX}"
    restore_folder = f"branch_{branch}/restored_{backup_timestamp}"
    os.makedirs(restore_folder, exist_ok=True)

    try:
        response = s3.list_objects_v2(
            Bucket=bucket_name,
            Prefix=f"{backup_timestamp}/"
        )

        if 'Contents' not in response:
            print(f"   No files found in backup {backup_timestamp}")
            return False

        print(f"\n🔄 Restoring {branch.upper()} from {backup_timestamp}...")
        for obj in response['Contents']:
            filename = obj['Key'].split('/')[-1]
            local_path = os.path.join(restore_folder, filename)
            s3.download_file(bucket_name, obj['Key'], local_path)
            print(f"   ✓ Restored {filename}")

        print(f"   ✅ Restore complete — files saved to {restore_folder}/")
        return True

    except Exception as e:
        print(f"   ✗ Restore failed: {e}")
        return False

if __name__ == "__main__":
    # Test — list backups for mumbai and restore latest
    backups = list_backups("mumbai")
    if backups:
        latest = sorted(backups)[-1]
        print(f"\nRestoring latest backup: {latest}")
        restore_backup("mumbai", latest)