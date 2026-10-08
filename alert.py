import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

SENDER = os.getenv("EMAIL_SENDER")
PASSWORD = os.getenv("EMAIL_PASSWORD")
RECEIVER = os.getenv("EMAIL_RECEIVER")

def send_alert(branch, alerts):
    try:
        subject = f"🚨 DISASTER ALERT — Branch {branch.upper()}"

        body = f"""
DISASTER RECOVERY SYSTEM — ALERT NOTIFICATION
===============================================
Branch     : {branch.upper()}
Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
===============================================

ALERTS DETECTED:
"""
        for i, alert in enumerate(alerts, 1):
            body += f"\n  {i}. {alert}"

        body += """

===============================================
ACTION TAKEN:
  → Backup triggered automatically
  → Data uploaded to AWS S3
  → This alert logged to audit trail

This is an automated message from the
Cloud Disaster Recovery System.
===============================================
"""

        msg = MIMEMultipart()
        msg['From'] = SENDER
        msg['To'] = RECEIVER
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER, PASSWORD)
        server.sendmail(SENDER, RECEIVER, msg.as_string())
        server.quit()

        print(f"   📧 Email alert sent successfully for {branch.upper()}")
        return True

    except Exception as e:
        print(f"   ✗ Email failed: {e}")
        return False

if __name__ == "__main__":
    # Test email
    print("Sending test email...")
    send_alert("mumbai", [
        "[CYBER] Cyber attack detected — 15 attempts in 3s",
        "[SYSTEM] High CPU: 90.05%"
    ])