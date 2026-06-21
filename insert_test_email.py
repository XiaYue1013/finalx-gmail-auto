#!/usr/bin/env python3
import sys
import os
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# 將當前路徑加入 sys.path 確保能 import app 包
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from app.gmail.auth import build_gmail_service
except ImportError:
    print("❌ 無法載入 app 模組，請確保在 FINALX_GMAIL_AUTO 根目錄下執行此腳本。")
    sys.exit(1)

def create_mime_message(sender, to, subject, body_html, attachment_name=None, attachment_content=b""):
    message = MIMEMultipart()
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject

    # 郵件正文
    msg_body = MIMEText(body_html, 'html', 'utf-8')
    message.attach(msg_body)

    # 處理附件 (選填)
    if attachment_name:
        mime_base = MIMEBase('application', 'octet-stream')
        mime_base.set_payload(attachment_content)
        encoders.encode_base64(mime_base)
        mime_base.add_header('Content-Disposition', f'attachment; filename="{attachment_name}"')
        message.attach(mime_base)

    # 轉為 base64url 編碼以符合 Gmail API 格式
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    return {'raw': raw_message}

def insert_message(service, message_body):
    try:
        # 將郵件插入到用戶的 INBOX，並標記為 UNREAD (未讀)
        result = service.users().messages().insert(
            userId='me',
            body={
                'raw': message_body['raw'],
                'labelIds': ['INBOX', 'UNREAD']
            }
        ).execute()
        print(f"✅ 成功插入郵件！Gmail Message ID: {result['id']}")
        return result
    except Exception as e:
        print(f"❌ 插入郵件失敗: {e}")
        return None

def main():
    print("====== Gmail API 本地測試郵件插入工具 ======")
    
    # 建立 Gmail API 客戶端
    try:
        service = build_gmail_service()
    except Exception as e:
        print(f"❌ 初始化 Gmail API 失敗: {e}")
        print("請確認是否已經產生 token.json 且憑證有效。")
        sys.exit(1)

    # 取得當前用戶的 Email 作為收件者
    try:
        profile = service.users().getProfile(userId='me').execute()
        my_email = profile.get('emailAddress')
        print(f"ℹ️ 偵測到當前授權的 Gmail 帳號: {my_email}")
    except Exception as e:
        print(f"⚠️ 無法取得用戶 Email，將預設使用 'me'。錯誤: {e}")
        my_email = "me"

    print("\n請選擇要模擬插入的郵件模板:")
    print("1) [高風險] 釣魚詐騙郵件 (安全登入警報，包含可疑連結)")
    print("2) [高風險] 惡意附件郵件 (包含 invoice.exe 危險副檔名)")
    print("3) [低風險] 一般正常郵件 (週會報告，內容安全)")
    print("4) 自訂郵件內容")

    choice = input("\n請輸入選項 (1-4): ").strip()

    sender = "no-reply@test-mail.example.test"
    to = my_email
    attachment_name = None
    attachment_content = b""

    if choice == "1":
        subject = "⚠️ [安全警告] 您的 Google 帳戶出現異常登入活動，請立即驗證！"
        body_html = """
        <html>
        <body>
            <h3>Google 帳戶安全警報</h3>
            <p>親愛的用戶，系統偵測到您的帳戶在未知的設備上嘗試登入。</p>
            <p><b>登入時間：</b> 2026-06-12 23:00 (GMT+8)<br>
            <b>登入 IP：</b> 192.168.99.123 (未知網段)</p>
            <p>如果您沒有進行此操作，請立即點擊下方連結驗證您的身份並更改密碼，否則帳戶將在 24 小時後被鎖定：</p>
            <p><a href="http://198.51.100.45/verify-account" style="background-color: red; color: white; padding: 10px; text-decoration: none; border-radius: 5px;">立即驗證帳戶</a></p>
            <br>
            <p>此郵件為系統自動發送，請勿直接回覆。</p>
        </body>
        </html>
        """
    elif choice == "2":
        subject = "Please find attached the invoice for your recent purchase"
        body_html = """
        <html>
        <body>
            <p>Dear Customer,</p>
            <p>Thank you for your business. Please find the attached invoice for your recent transaction.</p>
            <p>If you have any questions, please contact our support department.</p>
            <br>
            <p>Best regards,<br>Billing Department</p>
        </body>
        </html>
        """
        attachment_name = "invoice_2026_06_12.exe"
        attachment_content = b"This is a simulated payload for a malicious executable file."
    elif choice == "3":
        subject = "🎉 FINALX 專案開發進度週報"
        body_html = """
        <html>
        <body>
            <h3>開發團隊週報</h3>
            <p>各位好，本週我們完成了 Gmail API 的對接與測試，目前所有功能運行良好。</p>
            <p>下週預計進行最後一輪整合測試與簡報製作。</p>
            <br>
            <p>祝大家週末愉快！</p>
        </body>
        </html>
        """
    elif choice == "4":
        sender = input(f"寄件者 (預設: {sender}): ").strip() or sender
        subject = input("郵件主旨: ").strip() or "測試自訂郵件"
        body_text = input("郵件 HTML 內容: ").strip() or "<p>這是一封自訂測試郵件</p>"
        body_html = f"<html><body>{body_text}</body></html>"
        
        has_attach = input("是否包含附件? (y/n): ").strip().lower()
        if has_attach == "y":
            attachment_name = input("附件檔名 (例如 sample.js): ").strip() or "sample.txt"
            attachment_content = input("附件內容文字: ").encode('utf-8')
    else:
        print("❌ 無效的選項，程式結束。")
        sys.exit(1)

    print("\n正在生成並插入郵件...")
    print(f"From: {sender}")
    print(f"To: {to}")
    print(f"Subject: {subject}")
    if attachment_name:
        print(f"Attachment: {attachment_name}")

    msg_body = create_mime_message(sender, to, subject, body_html, attachment_name, attachment_content)
    insert_message(service, msg_body)

if __name__ == "__main__":
    main()
