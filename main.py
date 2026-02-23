#!/usr/bin/env python3
"""
Activity #3 - Multiprocessing tasks with timing

Tasks (each on its own subprocess):
  A) Compute SHA256 of winrar.exe and compare to expected hash.
  B) Compute factorials of [5, 7, 10, 12].
  C) Send an email containing the parent PID and all subprocess PIDs,
     including the time spent by each process.

This script is designed for Linux (as required), but works on most platforms.

How to run:
  1) Put winrar.exe in the SAME folder as this script (or pass --file PATH).
  2) Export SMTP environment variables (or run with --dry-run to skip sending).
  3) Run:
       python3 main.py --to instructor@example.com --from your_email@example.com

Environment variables (recommended):
  SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS
Optional:
  SMTP_USE_TLS=1   (STARTTLS; default)
  SMTP_USE_SSL=1   (SMTPS; if set, uses SSL instead of STARTTLS)
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import smtplib
import ssl
import time
from email.message import EmailMessage
from multiprocessing import Process, Queue
from typing import Dict, List, Tuple

EXPECTED_SHA256 = "DBC951B4AB01646888B2A91DA73A94DD920054C2F27C8CFEACAE3EBA298E71B0"


def _now() -> float:
    return time.perf_counter()


def sha256_worker(file_path: str, expected_hex: str, q: Queue) -> None:
    start = _now()
    pid = os.getpid()

    status = "ERROR"
    computed = ""
    message = ""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        computed = h.hexdigest().upper()

        if computed == expected_hex.upper():
            status = "OK"
            message = "File is OK"
        else:
            status = "MISMATCH"
            message = "Corrupted File"
    except FileNotFoundError:
        status = "NOT_FOUND"
        message = f"File not found: {file_path}"
    except Exception as e:
        status = "ERROR"
        message = f"Unexpected error: {e}"

    elapsed = _now() - start
    q.put(("sha256", pid, elapsed, {"status": status, "computed": computed, "message": message, "file": file_path}))


def factorial_worker(nums: List[int], q: Queue) -> None:
    start = _now()
    pid = os.getpid()

    results: Dict[int, int] = {}
    try:
        for n in nums:
            results[n] = math.factorial(n)
    except Exception as e:
        results = {"error": str(e)}  # type: ignore

    elapsed = _now() - start
    q.put(("factorial", pid, elapsed, {"inputs": nums, "results": results}))


def email_worker(
    parent_pid: int,
    subprocess_info: List[Tuple[str, int, float]],
    to_email: str,
    from_email: str,
    dry_run: bool,
    q: Queue,
) -> None:
    """
    subprocess_info: list of (task_name, pid, seconds)
    """
    start = _now()
    pid = os.getpid()

    # Build email body
    lines = []
    lines.append("Activity #3 - Process Report")
    lines.append("")
    lines.append(f"Parent PID: {parent_pid}")
    lines.append(f"Email subprocess PID: {pid}")
    lines.append("")
    lines.append("Subprocesses and time spent:")
    for task_name, spid, sec in subprocess_info:
        lines.append(f"- {task_name}: PID={spid}, time={sec:.6f} seconds")
    lines.append("")
    lines.append("Sent via Python smtplib.")

    subject = "Activity #3 - Parent/Subprocess PIDs and Timing"
    body = "\n".join(lines)

    send_status = {"sent": False, "details": ""}

    if dry_run:
        send_status = {"sent": False, "details": "DRY RUN: email not sent."}
    else:
        # SMTP config from env
        smtp_server = os.getenv("SMTP_SERVER", "")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER", "")
        smtp_pass = os.getenv("SMTP_PASS", "")

        use_ssl = os.getenv("SMTP_USE_SSL", "").strip() in ("1", "true", "TRUE", "yes", "YES")
        use_tls = os.getenv("SMTP_USE_TLS", "1").strip() in ("1", "true", "TRUE", "yes", "YES")

        if not smtp_server:
            send_status = {"sent": False, "details": "Missing SMTP_SERVER env var."}
        elif not smtp_user or not smtp_pass:
            send_status = {"sent": False, "details": "Missing SMTP_USER and/or SMTP_PASS env var."}
        else:
            try:
                msg = EmailMessage()
                msg["Subject"] = subject
                msg["From"] = from_email
                msg["To"] = to_email
                msg.set_content(body)

                context = ssl.create_default_context()

                if use_ssl:
                    # SMTPS (often port 465)
                    with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context, timeout=30) as server:
                        server.login(smtp_user, smtp_pass)
                        server.send_message(msg)
                else:
                    with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
                        server.ehlo()
                        if use_tls:
                            server.starttls(context=context)
                            server.ehlo()
                        server.login(smtp_user, smtp_pass)
                        server.send_message(msg)

                send_status = {"sent": True, "details": f"Email sent to {to_email}."}
            except Exception as e:
                send_status = {"sent": False, "details": f"Email send failed: {e}"}

    elapsed = _now() - start
    q.put(("email", pid, elapsed, {"to": to_email, "from": from_email, **send_status, "subject": subject}))


def main() -> int:
    parser = argparse.ArgumentParser(description="Activity #3 - subprocess tasks with timing")
    parser.add_argument("--file", default="winrar.exe", help="Path to winrar.exe (default: ./winrar.exe)")
    parser.add_argument("--to", default=os.getenv("TO_EMAIL", ""), help="Instructor email address (or set TO_EMAIL)")
    parser.add_argument("--from", dest="from_email", default=os.getenv("FROM_EMAIL", ""), help="Sender email (or set FROM_EMAIL)")
    parser.add_argument("--dry-run", action="store_true", help="Do not send email; just print it would send")
    args = parser.parse_args()

    parent_pid = os.getpid()

    # Queue for results from workers
    q: Queue = Queue()

    # Start task subprocesses (A and B)
    p_sha = Process(target=sha256_worker, args=(args.file, EXPECTED_SHA256, q), name="sha256_proc")
    p_fact = Process(target=factorial_worker, args=([5, 7, 10, 12], q), name="factorial_proc")

    t0 = _now()
    p_sha.start()
    p_fact.start()

    # Collect results for A and B
    results = {}
    subprocess_timings: List[Tuple[str, int, float]] = []
    for _ in range(2):
        task, pid, elapsed, payload = q.get()
        results[task] = payload
        subprocess_timings.append((task, pid, elapsed))

    # Ensure they exit
    p_sha.join()
    p_fact.join()

    # Print outputs from tasks
    print("=" * 60)
    print(f"Parent PID: {parent_pid}")
    print("=" * 60)

    # A) SHA256
    sha = results.get("sha256", {})
    print("[A] SHA256 check")
    print(f"  File: {sha.get('file', args.file)}")
    print(f"  Expected: {EXPECTED_SHA256}")
    print(f"  Computed: {sha.get('computed', '')}")
    print(f"  Result: {sha.get('message', '')}")
    print()

    # B) Factorials
    fact = results.get("factorial", {})
    print("[B] Factorials")
    inputs = fact.get("inputs", [])
    fact_results = fact.get("results", {})
    for n in inputs:
        print(f"  {n}! = {fact_results.get(n)}")
    print()

    # C) Email - validate args early
    if not args.to:
        print("[C] Email")
        print("  Missing --to (instructor email). Provide --to or set TO_EMAIL.")
        print("  Email will be skipped (treated as dry-run).")
        args.dry_run = True
        args.to = "instructor@example.com"

    if not args.from_email:
        print("[C] Email")
        print("  Missing --from (sender email). Provide --from or set FROM_EMAIL.")
        print("  Email may fail to send depending on SMTP provider.")
        if args.dry_run:
            args.from_email = "you@example.com"

    # Start email subprocess AFTER A and B so the email can include their times
    p_email = Process(
        target=email_worker,
        args=(parent_pid, subprocess_timings, args.to, args.from_email, args.dry_run, q),
        name="email_proc",
    )
    p_email.start()

    # Get email result
    task, pid, elapsed, payload = q.get()
    results[task] = payload
    subprocess_timings.append((task, pid, elapsed))

    p_email.join()

    # Print email status
    print("[C] Email")
    print(f"  To: {payload.get('to')}")
    print(f"  From: {payload.get('from')}")
    print(f"  Status: {'SENT' if payload.get('sent') else 'NOT SENT'}")
    print(f"  Details: {payload.get('details')}")
    print()

    # Print timing summary (required)
    print("=" * 60)
    print("Timing summary (seconds)")
    for task_name, spid, sec in subprocess_timings:
        print(f"- {task_name}: PID={spid}, time={sec:.6f}")
    print("=" * 60)

    total = _now() - t0
    print(f"Total wall time (parent perspective): {total:.6f} seconds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
