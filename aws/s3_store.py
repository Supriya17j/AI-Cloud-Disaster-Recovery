"""AWS S3 storage. Credentials only from environment variables."""
import os, logging
log = logging.getLogger(__name__)

def _client():
    import boto3
    return boto3.client("s3", aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                        region_name=os.getenv("AWS_REGION"))

def _bucket():
    b = os.getenv("AWS_BUCKET_NAME")
    if not b: raise RuntimeError("AWS_BUCKET_NAME not set")
    return b

def upload_backup(backup_id, folder):
    c = _client()
    for f in os.listdir(folder):
        c.upload_file(os.path.join(folder, f), _bucket(), f"{backup_id}/{f}")
    log.info("Uploaded %s to S3", backup_id)

def download_backup(backup_id, dest):
    c = _client(); os.makedirs(dest, exist_ok=True)
    for o in c.list_objects_v2(Bucket=_bucket(), Prefix=backup_id + "/").get("Contents", []):
        c.download_file(_bucket(), o["Key"], os.path.join(dest, os.path.basename(o["Key"])))

def list_backups():
    r = _client().list_objects_v2(Bucket=_bucket(), Delimiter="/")
    return [p["Prefix"].rstrip("/") for p in r.get("CommonPrefixes", [])]


def upload_demo_file(file_path, object_key):
    """Upload a demo/test artifact only; it is never treated as a recovery backup."""
    c = _client()
    c.upload_file(file_path, _bucket(), object_key)
    log.info("Uploaded demo artifact %s", object_key)
