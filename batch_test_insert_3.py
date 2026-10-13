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

# 第三波測試信模版：探討政府退稅詐騙、Unicode 混淆字元、巨集啟用檔案、跳轉 URL、MFA 二次驗證釣魚、CEO 社交工程及求職詐騙等情境。
TEST_EMAILS_3 = [
    {
        "id": 1,
        "type": "高風險 (High Risk - 政府退稅詐騙)",
        "sender": "tax-refund@gov-portal-tax.xiayue.tw",
        "subject": "通知：您有新台幣 12,500 元的個人所得稅退稅未領取",
        "body": """
        <html>
        <body>
            <div style="border: 2px solid #005a9c; padding: 20px; font-family: sans-serif;">
                <h2 style="color: #005a9c;">財政部電子申報繳稅服務網通知</h2>
                <p>親愛的納稅義務人，系統偵測到您有一筆過期未領取的個人所得稅退稅，金額共計新台幣 <b>12,500 元整</b>。</p>
                <p>請於 3 日內前往下方財政部指定退稅網站填寫您的銀行帳戶資料，以利完成退稅匯款手續：</p>
                <p><a href="http://gov-portal-tax.xyz/claim" style="background-color: #005a9c; color: white; padding: 10px 20px; text-decoration: none; font-weight: bold; border-radius: 4px; display: inline-block;">立即領取退稅款項項目</a></p>
                <p>※ 逾期未申領者，該筆退稅款將依法解繳國庫，恕不另行通知。</p>
            </div>
        </body>
        </html>
        """
    },
    {
        "id": 2,
        "type": "中風險 (Medium Risk - Unicode 偽造混淆字元)",
        "sender": "promotion@discounts-deal.xiayue.tw",
        "subject": "【重要】𝖦𝖾𝗍 𝟧𝟢% 𝖮𝖿𝖿 on your next order - 𝖫𝗂𝗆𝗂𝗍𝖾𝖽 𝖳𝗂𝗆𝖾",
        "body": """
        <html>
        <body>
            <h3>𝖲𝗉𝖾𝖼𝗂𝖺𝗅 𝖮𝖿𝖿𝖾𝗋 for loyal customers!</h3>
            <p>We are offering 50% discount on all software licenses. Use promo code <b>HALFPRICE</b> at checkout.</p>
            <p>Click here to buy: <a href="http://discounts-deal.xiayue.tw/buy">Buy Software Now</a></p>
        </body>
        </html>
        """
    },
    {
        "id": 3,
        "type": "安全 (Low Risk)",
        "sender": "alerts@uptime-robot.com",
        "subject": "Monitor is UP: FinalX Production Server (https://api.finalx.tw)",
        "body": """
        <html>
        <body>
            <div style="font-family: Arial; padding: 15px; border: 1px solid #d4edda; background-color: #d4edda; color: #155724; border-radius: 4px;">
                <strong>Monitor is UP</strong> (api.finalx.tw is back online)
            </div>
            <p>The monitor <b>FinalX Production Server</b> was down for 2 minutes and 15 seconds, but it has now recovered successfully.</p>
            <p>Timestamp: 2026-06-12 23:58 (GMT+8)</p>
        </body>
        </html>
        """
    },
    {
        "id": 4,
        "type": "高風險 (High Risk - 巨集啟用試算表 / 潛在惡意 VBA 巨集)",
        "sender": "reports@corp-accounting.xiayue.tw",
        "subject": "CONFIDENTIAL: Q1 Financial Performance & Audit Reports",
        "body": """
        <html>
        <body>
            <p>Hi Team,</p>
            <p>Please review the attached Q1 financial performance audit reports. Since this spreadsheet contains automated VBA scripts to pull live database metrics, please make sure you <b>"Enable Content (Macros)"</b> when opening the file.</p>
            <p>Do not distribute this file outside the core management group.</p>
        </body>
        </html>
        """,
        "attachment_name": "Q1_Report_Secure.xlsm",
        "attachment_content": b"[Simulated Excel Macro Document Binary Content]"
    },
    {
        "id": 5,
        "type": "中風險 (Medium Risk - 可疑的跳轉 Redirect 連結)",
        "sender": "no-reply@social-network.xiayue.tw",
        "subject": "You have 3 new notifications waiting on your feed",
        "body": """
        <html>
        <body>
            <p>You have new interactions waiting on your social profile. People are looking at your recent post!</p>
            <p>Click below to view notifications:</p>
            <p><a href="http://gooddomain.com/redirect?url=http://suspicious-target.com/phish">View My Feed & Notifications</a></p>
        </body>
        </html>
        """
    },
    {
        "id": 6,
        "type": "安全 (Low Risk)",
        "sender": "newsletter@medium.com",
        "subject": "Medium: 5 Python tips you should know in 2026",
        "body": """
        <html>
        <body>
            <h3>Stories for Today</h3>
            <h4>1. Modern Python Features in 3.13 and 3.14</h4>
            <p>Discover how the GIL removal and new JIT compiler affect performance.</p>
            <h4>2. Designing Agentic Workflows</h4>
            <p>A deep dive into tool selection, subagents, and self-correcting logic.</p>
            <p>Read more on <a href="https://medium.com">Medium</a>.</p>
        </body>
        </html>
        """
    },
    {
        "id": 7,
        "type": "高風險 (High Risk - MFA 驗證釣魚)",
        "sender": "auth-security@microsoft-mfa.xiayue.tw",
        "subject": "Action Required: Re-authenticate your Multi-Factor Authentication (MFA) immediately",
        "body": """
        <html>
        <body>
            <p>Dear User,</p>
            <p>Due to recent security policy upgrades, we require all users to re-validate their Multi-Factor Authentication (MFA) settings within 12 hours.</p>
            <p>Failure to complete re-authentication will result in temporary suspension of your corporate Office 365 and Outlook access.</p>
            <p><a href="http://mfa-verification-microsoft.com/login" style="background-color: #0078d4; color: white; padding: 8px 16px; text-decoration: none; font-weight: bold; border-radius: 2px; display: inline-block;">Re-authenticate MFA</a></p>
        </body>
        </html>
        """
    },
    {
        "id": 8,
        "type": "安全 (Low Risk)",
        "sender": "gitlab@xiayue.tw",
        "subject": "Re: GitLab Issue #42: Bug in Gmail Watch refresh task",
        "body": """
        <html>
        <body>
            <p><b>@xiayue</b> commented on Issue #42:</p>
            <blockquote style="border-left: 3px solid #0052cc; padding-left: 10px; color: #555;">
                "I investigated the token expiration logic. The token is successfully refreshed now using credentials.json. Let's merge the branch."
            </blockquote>
            <p>View issue thread: <a href="https://gitlab.xiayue.tw/issues/42">GitLab Issue #42</a></p>
        </body>
        </html>
        """
    },
    {
        "id": 9,
        "type": "高風險 (High Risk - CEO 社交工程詐騙)",
        "sender": "ceo-office@ceo-corporate-xiayue.tw",
        "subject": "URGENT REQUEST: Immediate wire transfer needed for project acquisition",
        "body": """
        <html>
        <body>
            <p>Hi,</p>
            <p>I am currently attending a confidential board meeting and cannot take any calls. However, we need to settle an urgent acquisition payment today to secure the transaction.</p>
            <p>Please prepare a wire transfer of <b>$25,000 USD</b> to the escrow bank account details attached in the file.</p>
            <p>Let me know as soon as the transfer is processed. Speed is critical.</p>
            <br>
            <p>Best regards,<br>CEO Office</p>
        </body>
        </html>
        """
    },
    {
        "id": 10,
        "type": "中風險 (Medium Risk - 求職行銷詐騙)",
        "sender": "recruiter@job-search.xiayue.tw",
        "subject": "Work from home job opportunity: Earn up to $3000/week part-time",
        "body": """
        <html>
        <body>
            <h3>Start Earning Today!</h3>
            <p>We are seeking remote online assistants to evaluate app products and write short feedback reviews.</p>
            <ul>
                <li>Flexible hours (1-2 hours per day)</li>
                <li>Weekly payouts</li>
                <li>No experience required</li>
            </ul>
            <p>Contact our hiring manager on Telegram now: <a href="https://t.me/job_recruit_online">Contact Recruiter</a></p>
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
    print("      📧 開始第三波批次郵件插入 (共 10 封)      ")
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

    for i, mail in enumerate(TEST_EMAILS_3):
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

        if i < len(TEST_EMAILS_3) - 1:
            print(f"   ⏳ 等待 {TEST_EMAIL_INTERVAL_SECONDS} 秒後發送下一封...")
            for sec in range(TEST_EMAIL_INTERVAL_SECONDS, 0, -1):
                sys.stdout.write(f"\r      剩餘 {sec} 秒...")
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write("\r")
            sys.stdout.flush()

    print("\n==================================================")
    print("🎉 第三波 10 封測試信件已全部插入完畢！")
    print("==================================================")

if __name__ == "__main__":
    main()
