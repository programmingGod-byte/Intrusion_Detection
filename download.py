import os
import time
import boto3
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ============================================================
# AWS CREDENTIALS
# ============================================================

AWS_ACCESS_KEY_ID = "AKIARTXU7T2CTU2LRLIZ"
AWS_SECRET_ACCESS_KEY = "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"
AWS_REGION = "ap-south-1"

# ============================================================
# BUCKETS
# ============================================================

BUCKETS = [
    "backup-kamamd-new",
    "backup-kamand",
    "north-campus"
]

# ============================================================
# SPEED SETTINGS
# ============================================================

# Increase this if your internet is fast.
# Try 32, 50, or 64.
MAX_WORKERS = 50

# Multipart settings for large files
MULTIPART_THRESHOLD = 8 * 1024 * 1024
MULTIPART_CHUNKSIZE = 8 * 1024 * 1024

# ============================================================
# S3
# ============================================================

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

# ============================================================
# DOWNLOAD LOCATION
# ============================================================

# Same folder where this Python file is running
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DOWNLOAD_DIR = os.path.join(BASE_DIR, "downloads")

os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# ============================================================
# HELPERS
# ============================================================

lock = Lock()

downloaded_bytes = 0
completed_files = 0


def format_size(size):
    """Convert bytes to readable size."""

    if size < 1024:
        return f"{size:.0f} B"

    if size < 1024 ** 2:
        return f"{size / 1024:.2f} KB"

    if size < 1024 ** 3:
        return f"{size / 1024**2:.2f} MB"

    if size < 1024 ** 4:
        return f"{size / 1024**3:.2f} GB"

    return f"{size / 1024**4:.2f} TB"


def format_time(seconds):

    if seconds == float("inf"):
        return "--"

    seconds = int(seconds)

    days = seconds // 86400
    seconds %= 86400

    hours = seconds // 3600
    seconds %= 3600

    minutes = seconds // 60
    seconds %= 60

    if days:
        return f"{days}d {hours}h {minutes}m"

    if hours:
        return f"{hours}h {minutes}m {seconds}s"

    if minutes:
        return f"{minutes}m {seconds}s"

    return f"{seconds}s"


# ============================================================
# GET ALL OBJECTS
# ============================================================

def get_bucket_objects(bucket):

    print(f"\nScanning bucket: {bucket}")

    objects = []

    paginator = s3.get_paginator("list_objects_v2")

    for page in paginator.paginate(Bucket=bucket):

        for obj in page.get("Contents", []):

            key = obj["Key"]
            size = obj["Size"]

            # Ignore folder markers
            if key.endswith("/"):
                continue

            objects.append({
                "key": key,
                "size": size
            })

    return objects


# ============================================================
# DOWNLOAD ONE FILE
# ============================================================

def download_file(bucket, obj, bucket_dir):

    global downloaded_bytes
    global completed_files

    key = obj["key"]
    remote_size = obj["size"]

    local_file = os.path.join(bucket_dir, key)

    os.makedirs(
        os.path.dirname(local_file),
        exist_ok=True
    )

    # Already downloaded?
    if os.path.exists(local_file):

        local_size = os.path.getsize(local_file)

        if local_size == remote_size:

            with lock:
                downloaded_bytes += remote_size
                completed_files += 1

            return "skipped"

    try:

        # Create separate S3 client for each worker.
        # This helps when many threads are active.
        client = boto3.client(
            "s3",
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )

        from boto3.s3.transfer import TransferConfig

        config = TransferConfig(
            multipart_threshold=MULTIPART_THRESHOLD,
            multipart_chunksize=MULTIPART_CHUNKSIZE,
            max_concurrency=10,
            use_threads=True
        )

        client.download_file(
            bucket,
            key,
            local_file,
            Config=config
        )

        with lock:
            downloaded_bytes += remote_size
            completed_files += 1

        return "downloaded"

    except Exception as e:

        print(f"\nERROR: {key}")
        print(e)

        return "failed"


# ============================================================
# DOWNLOAD BUCKET
# ============================================================

def download_bucket(bucket):

    global downloaded_bytes
    global completed_files

    downloaded_bytes = 0
    completed_files = 0

    # --------------------------------------------------------
    # Get objects
    # --------------------------------------------------------

    objects = get_bucket_objects(bucket)

    total_size = sum(obj["size"] for obj in objects)

    total_files = len(objects)

    print("\n" + "=" * 70)
    print(f"BUCKET: {bucket}")
    print("=" * 70)

    print(f"Files       : {total_files:,}")
    print(f"Total size  : {format_size(total_size)}")
    print(f"Workers     : {MAX_WORKERS}")

    if total_files == 0:

        print("Bucket is empty.")
        return

    bucket_dir = os.path.join(
        DOWNLOAD_DIR,
        bucket
    )

    os.makedirs(bucket_dir, exist_ok=True)

    # --------------------------------------------------------
    # Start
    # --------------------------------------------------------

    start_time = time.time()

    print("\nStarting download...\n")

    # --------------------------------------------------------
    # Parallel downloads
    # --------------------------------------------------------

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = []

        for obj in objects:

            future = executor.submit(
                download_file,
                bucket,
                obj,
                bucket_dir
            )

            futures.append(future)

        # ----------------------------------------------------
        # Monitor progress
        # ----------------------------------------------------

        last_display = 0

        for future in as_completed(futures):

            try:
                future.result()
            except Exception as e:
                print(f"\nWorker error: {e}")

            now = time.time()

            # Don't print 50 lines per second
            if now - last_display >= 1:

                last_display = now

                with lock:

                    current_downloaded = downloaded_bytes
                    current_files = completed_files

                elapsed = now - start_time

                speed = (
                    current_downloaded / elapsed
                    if elapsed > 0
                    else 0
                )

                remaining = max(
                    total_size - current_downloaded,
                    0
                )

                percent = (
                    current_downloaded / total_size * 100
                    if total_size > 0
                    else 100
                )

                eta = (
                    remaining / speed
                    if speed > 0
                    else float("inf")
                )

                print(
                    f"\r"
                    f"Progress: {percent:6.2f}% | "
                    f"Files: {current_files:,}/{total_files:,} | "
                    f"Downloaded: {format_size(current_downloaded)} | "
                    f"Remaining: {format_size(remaining)} | "
                    f"Speed: {format_size(speed)}/s | "
                    f"ETA: {format_time(eta)}",
                    end="",
                    flush=True
                )

    # --------------------------------------------------------
    # Finished
    # --------------------------------------------------------

    elapsed = time.time() - start_time

    print("\n\n" + "=" * 70)
    print(f"✓ FINISHED: {bucket}")
    print("=" * 70)

    print(f"Total size : {format_size(total_size)}")
    print(f"Files      : {total_files:,}")
    print(f"Time       : {format_time(elapsed)}")

    if elapsed > 0:

        avg_speed = total_size / elapsed

        print(
            f"Avg speed  : {format_size(avg_speed)}/s"
        )

    print(
        f"Location   : {bucket_dir}"
    )


# ============================================================
# MAIN
# ============================================================

print("=" * 70)
print("S3 BULK DOWNLOADER")
print("=" * 70)

print(f"Region     : {AWS_REGION}")
print(f"Download   : {DOWNLOAD_DIR}")
print(f"Workers    : {MAX_WORKERS}")

for bucket in BUCKETS:

    answer = input(
        f"\nDownload '{bucket}'? [y/N]: "
    )

    if answer.lower() == "y":

        try:
            download_bucket(bucket)

        except Exception as e:

            print(
                f"\n✗ Failed bucket: {bucket}"
            )

            print(e)

    else:

        print(f"Skipped: {bucket}")


print("\nAll selected buckets processed.")