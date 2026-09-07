"""
storage/s3_client.py

Thin wrapper around boto3 for generating presigned S3 download URLs.
This is the ONLY way the broker should ever hand out access to an object —
never return a permanent public URL.

Auth: boto3 picks up credentials automatically from (in order of preference):
  1. Environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
  2. A named profile via AWS_PROFILE env var (from `aws configure --profile <name>`)
  3. ~/.aws/credentials default profile
Never hardcode keys in this file.
"""

import os
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

load_dotenv()  # pulls values from a local .env file if present

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
DEFAULT_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

_s3_client = None


def get_s3_client():
    """Lazily create and cache a single boto3 S3 client.

    Explicitly pins endpoint_url to the regional S3 endpoint. Some botocore
    versions otherwise build presigned URLs against the legacy global
    endpoint (s3.amazonaws.com) while signing for the regional one
    (s3.<region>.amazonaws.com), causing SignatureDoesNotMatch for any
    bucket outside us-east-1. Pinning the endpoint keeps both consistent.
    """
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client(
            "s3",
            region_name=AWS_REGION,
            endpoint_url=f"https://s3.{AWS_REGION}.amazonaws.com",
        )
    return _s3_client


def generate_presigned_url(object_key: str, expiry_seconds: int = 60, bucket_name: str = None) -> str:
    """
    Generate a time-limited presigned URL that allows a GET on a single S3 object.

    Args:
        object_key: the key (path) of the object inside the bucket, e.g. "scan1.pdf".
        expiry_seconds: how many seconds the URL stays valid. Default 60.
        bucket_name: override the bucket from S3_BUCKET_NAME env var if needed.

    Returns:
        A presigned HTTPS URL string.

    Raises:
        ValueError: if no bucket is configured.
        RuntimeError: if AWS rejects the request (bad credentials, bad key, etc.)
    """
    bucket = bucket_name or DEFAULT_BUCKET_NAME
    if not bucket:
        raise ValueError(
            "No S3 bucket configured. Set S3_BUCKET_NAME in your .env file "
            "or pass bucket_name explicitly."
        )

    client = get_s3_client()
    try:
        url = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": object_key},
            ExpiresIn=expiry_seconds,
        )
        return url
    except NoCredentialsError as e:
        raise RuntimeError(
            "No AWS credentials found. Run `aws configure` or set "
            "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY."
        ) from e
    except ClientError as e:
        raise RuntimeError(f"Failed to generate presigned URL for '{object_key}': {e}") from e


if __name__ == "__main__":
    # Quick manual smoke test: python s3_client.py <object_key>
    import sys

    key = sys.argv[1] if len(sys.argv) > 1 else "test1.txt"
    print(generate_presigned_url(key, expiry_seconds=60))