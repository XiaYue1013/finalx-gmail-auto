#!/usr/bin/env python3
import sys
import os
import time
import base64
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from app.gmail.auth import build_gmail_service
except ImportError:
    print("❌ 無法載入 app 模組，請確保在 FINALX_GMAIL_AUTO 根目錄下執行此腳本。")
    sys.exit(1)

# 第二波測試信模版：探討仿冒網域、隱形追蹤像素、雙重副檔名、高風險頂級網域、勒索恐嚇及表單釣魚等不同情境。
TEST_EMAILS_2 = [
    {
        "id": 1,
        "type": "高風險 (High Risk - 品牌仿冒與相似網域)",
        "sender": "accounts@g00gle.support.example.test",
        "subject": "Critical security alert: Unauthorized password change attempt detected",
        "body": """
        <html>
        <body>
            <div style="font-family: Roboto, sans-serif; padding: 20px; border: 1px solid #eee;">
                <h2 style="color: #d93025;">Google Account Alert</h2>
                <p>Someone recently tried to change your Google account password from an unrecognized IP address in Russia.</p>
                <p>If this was not you, please secure your account immediately by verifying your current login details:</p>
                <p><a href="https://g00gle.security-setting.com/recovery" style="background-color: #1a73e8; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px; display: inline-block;">Secure My Account</a></p>
                <p>Thanks,<br>The Google Accounts team</p>
            </div>
        </body>
        </html>
        """
    },
    {
        "id": 2,
        "type": "中風險 (Medium Risk - 行銷垃圾郵件與追蹤像素)",
        "sender": "sales@amazingdeals.example.test",
        "subject": "Congratulations! You won a brand new iPhone 17 Pro Max!",
        "body": """
        <html>
        <body>
            <h3>Dear Lucky User,</h3>
            <p>You have been randomly selected as our grand prize winner of the day!</p>
            <p>Claim your reward now by registering your shipping details here: <a href="http://winner-claims.com/iphone">Claim Reward</a></p>
            <!-- 隱形追蹤像素測試 -->
            <img src="http://amazingdeals.example.test/track/pixel.gif?id=123" width="1" height="1" style="display:none;" />
        </body>
        </html>
        """
    },
    {
        "id": 3,
        "type": "安全 (Low Risk)",
        "sender": "billing@github.com",
        "subject": "[GitHub] Your monthly receipt for June 2026",
        "body": """
        <html>
        <body>
            <h3>GitHub Receipt - June 2026</h3>
            <p>Thanks for using GitHub! This is a receipt for your monthly payment.</p>
            <table border="1" cellpadding="5" style="border-collapse: collapse;">
                <tr><th>Description</th><th>Amount</th></tr>
                <tr><td>GitHub Copilot Subscription</td><td>$10.00</td></tr>
                <tr><td><b>Total Paid</b></td><td><b>$10.00</b></td></tr>
            </table>
            <p>You can view your billing history or change your payment method on <a href="https://github.com/settings/billing">GitHub Billing Settings</a>.</p>
        </body>
        </html>
        """
    },
    {
        "id": 4,
        "type": "高風險 (High Risk - 雙重副檔名 / 偽裝成 PDF 的快捷方式)",
        "sender": "legal-notice@example.test",
        "subject": "NOTICE: Immediate copyright infringement cease and desist",
        "body": """
        <html>
        <body>
            <p>Dear Administrator,</p>
            <p>It has come to our attention that your site hosts copyrighted materials without authorization.</p>
            <p>Please refer to the legal claim details and image evidence in the attachment. Remove them immediately to avoid a formal lawsuit.</p>
        </body>
        </html>
        """,
        "attachment_name": "legal_claim_evidence.pdf.lnk",
        "attachment_content": b"[Simulated Windows Shortcut Executable Payload]"
    },
    {
        "id": 5,
        "type": "中風險 (Medium Risk - 高風險 TLD zip 網域)",
        "sender": "freelance@work.example.test",
        "subject": "Project Proposal details for review",
        "body": """
        <html>
        <body>
            <p>Hi,</p>
            <p>I have prepared the project timeline and draft contract files for the upcoming software development. Please review them directly on my cloud folder:</p>
            <p>Link: <a href="http://my-proposal-project.zip">http://my-proposal-project.zip</a></p>
            <br>
            <p>Best regards,<br>Freelancer Team</p>
        </body>
        </html>
        """
    },
    {
        "id": 6,
        "type": "安全 (Low Risk)",
        "sender": "colleague-lisa@example.test",
        "subject": "Invitation: Project FinalX Architecture Review @ Mon Jun 15",
        "body": """
        <html>
        <body>
            <h3>Meeting Invitation</h3>
            <p>Hi Team,</p>
            <p>Please join the architectural review meeting next Monday to discuss the Pub/Sub workflow and label structures.</p>
            <p><b>Time:</b> 14:00 - 15:30 (GMT+8)<br>
            <b>Link:</b> Google Meet (internal channel)</p>
        </body>
        </html>
        """
    },
    {
        "id": 7,
        "type": "高風險 (High Risk - 比特幣勒索威脅信)",
        "sender": "anonymous-hacker@protonmail.com",
        "subject": "YOUR FILES ARE ENCRYPTED - Read immediately",
        "body": """
        <html>
        <body>
            <h3>CRITICAL SECURITY NOTICE</h3>
            <p>All your network files, source code, and databases have been encrypted by ransomware.</p>
            <p>To decrypt your data, you must pay 0.5 BTC to the following Bitcoin address within 48 hours:</p>
            <p><b>BTC Address:</b> bc1qxy2kg3ck46kk9t3236kcs5kkkkkkkkkkkkkkk</p>
            <p>If you fail to pay, we will release your private databases to the public internet.</p>
        </body>
        </html>
        """
    },
    {
        "id": 8,
        "type": "安全 (Low Risk)",
        "sender": "notification@slack.com",
        "subject": "[Slack] New messages from Alice in #finalx-project",
        "body": """
        <html>
        <body>
            <h3>New notifications on Slack</h3>
            <p><b>Alice</b> sent a message in <b>#finalx-project</b>:</p>
            <blockquote style="border-left: 3px solid #ddd; padding-left: 10px;">
                "I've pushed the local API test script. Let me know if it works on your side!"
            </blockquote>
            <p><a href="https://slack.com/app_redirect?channel=finalx-project" style="background-color: #4a154b; color: white; padding: 8px 12px; text-decoration: none; border-radius: 4px; display: inline-block;">Reply on Slack</a></p>
        </body>
        </html>
        """
    },
    {
        "id": 9,
        "type": "高風險 (High Risk - 表單與網頁付款釣魚)",
        "sender": "verification@netflix-update.example.test",
        "subject": "Update your Netflix billing information to avoid account suspension",
        "body": """
        <html>
        <body>
            <h3>Netflix Account Update</h3>
            <p>We were unable to process your monthly membership payment. To continue enjoying Netflix, please update your credit card details immediately.</p>
            <p>Verify your details directly at our secure portal:</p>
            <p><a href="https://netflix-payment-update.example.test/login" style="background-color: #e50914; color: white; padding: 10px 15px; text-decoration: none; font-weight: bold; border-radius: 4px; display: inline-block;">Update Payment Method</a></p>
            <p>Failure to update your payment information will result in immediate termination of your subscription.</p>
        </body>
        </html>
        """
    },
    {
        "id": 10,
        "type": "中風險 (Medium Risk - 加密貨幣空投與行銷詐騙)",
        "sender": "airdrops@solana-giveaway.example.test",
        "subject": "Claim your $500 SOL Airdrop instantly before it expires!",
        "body": """
        <html>
        <body>
            <h3>Solana Airdrop Live!</h3>
            <p>To celebrate our platform launch, we are giving away $500 USD value in SOL to the first 10,000 active web3 wallets.</p>
            <p>Connect your Phantom or Metamask wallet here to claim yours today:</p>
            <p><a href="http://solana-claim-airdrop.win/connect">Connect Wallet & Claim SOL</a></p>
            <p>Don't miss out on this lifetime opportunity!</p>
        </body>
        </html>
        """
    }
]

TEST_EMAIL_INTERVAL_SECONDS = 2

def create_mime_message(sender, to, subject, body_html, reply_to=None, attachment_name=None, attachment_content=b""):
    message = MIMEMultipart()
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    if reply_to:
        message['reply-to'] = reply_to

    msg_body = MIMEText(body_html, 'html', 'utf-8')
    message.attach(msg_body)

    if attachment_name:
        mime_base = MIMEBase('application', 'octet-stream')
        mime_base.set_payload(attachment_content)
        encoders.encode_base64(mime_base)
        mime_base.add_header('Content-Disposition', f'attachment; filename="{attachment_name}"')
        message.attach(mime_base)

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    return {'raw': raw_message}

def insert_message(service, message_body):
    try:
        result = service.users().messages().insert(
            userId='me',
            body={
                'raw': message_body['raw'],
                'labelIds': ['INBOX', 'UNREAD']
            }
        ).execute()
        return result['id']
    except Exception as e:
        print(f"❌ 插入郵件失敗: {e}")
        return None

def main():
    print("==================================================")
    print("      📧 開始第二波批次郵件插入 (共 10 封)      ")
    print(f"      間隔設定: {TEST_EMAIL_INTERVAL_SECONDS} 秒 | 目前時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}      ")
    print("==================================================")

    try:
        service = build_gmail_service()
    except Exception as e:
        print(f"❌ 初始化 Gmail API 失敗: {e}")
        sys.exit(1)

    try:
        profile = service.users().getProfile(userId='me').execute()
        my_email = profile.get('emailAddress')
        print(f"👉 目標收件匣: {my_email}")
    except Exception as e:
        my_email = "me"
        print(f"⚠️ 無法取得用戶 Email，將預設使用 'me'。")

    print("--------------------------------------------------")

    for i, mail in enumerate(TEST_EMAILS_2):
        idx = mail["id"]
        sender = mail["sender"]
        subject = mail["subject"]
        body = mail["body"]
        mail_type = mail["type"]
        attachment_name = mail.get("attachment_name")
        attachment_content = mail.get("attachment_content", b"")

        print(f"\n[{idx}/10] 正在插入郵件...")
        print(f"   類型: {mail_type}")
        print(f"   寄件者: {sender}")
        print(f"   主旨: {subject}")
        if attachment_name:
            print(f"   附件: {attachment_name}")

        msg_body = create_mime_message(
            sender=sender,
            to=my_email,
            subject=subject,
            body_html=body,
            attachment_name=attachment_name,
            attachment_content=attachment_content
        )

        gmail_id = insert_message(service, msg_body)
        if gmail_id:
            print(f"   ✅ 成功插入！Gmail ID: {gmail_id}")
        else:
            print(f"   ❌ 插入失敗。")

        if i < len(TEST_EMAILS_2) - 1:
            print(f"   ⏳ 等待 {TEST_EMAIL_INTERVAL_SECONDS} 秒後發送下一封...")
            for sec in range(TEST_EMAIL_INTERVAL_SECONDS, 0, -1):
                sys.stdout.write(f"\r      剩餘 {sec} 秒...")
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write("\r")
            sys.stdout.flush()

    print("\n==================================================")
    print("🎉 第二波 10 封測試信件已全部插入完畢！")
    print("==================================================")

if __name__ == "__main__":
    main()
