#!/usr/bin/env python3
import argparse
import sys
import os
import time
import base64
from datetime import datetime
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

from batch_test_insert_2 import TEST_EMAILS_2
from batch_test_insert_3 import TEST_EMAILS_3

# 定義 10 封測試信的模版列表
# 包含 4 封安全信、2 封中風險、4 封高風險 (包括釣魚連結、Reply-To不一致、危險附件)
TEST_EMAILS = [
    {
        "id": 1,
        "type": "安全 (Low Risk)",
        "sender": "newsletter@techtrends.xiayue.tw",
        "subject": "週五技術快報：AI 領域的最新進展與工具推薦",
        "body": """
        <html>
        <body>
            <h3>技術團隊週報</h3>
            <p>各位好，本週我們收集了 AI 領域的熱門討論，包含大型語言模型推理速度的突破，以及多款實用的開發工具。</p>
            <p>詳情請參閱內部 wiki 文件或點擊我們的官方部落格閱讀。</p>
            <br>
            <p>祝大家週末愉快！</p>
        </body>
        </html>
        """
    },
    {
        "id": 2,
        "type": "高風險 (High Risk - 釣魚連結)",
        "sender": "security@bank-verify.xiayue.tw",
        "subject": "🚨 [重要安全通報] 您的網路銀行帳戶已被暫時限制登入",
        "body": """
        <html>
        <body>
            <h3 style="color: red;">網路銀行帳戶異常登入警告</h3>
            <p>親愛的用戶，系統偵測到您的帳戶在多個地區同時嘗試登入，為保護您的資金安全，我們已暫時限制您的轉帳功能。</p>
            <p>請立即點擊下方按鈕，於 24 小時內驗證您的身分以解除限制：</p>
            <p><a href="http://198.51.100.45/verify-account" style="background-color: #d9534f; color: white; padding: 12px 20px; text-decoration: none; display: inline-block; font-weight: bold; border-radius: 5px;">立即解除限制</a></p>
            <p>若未在限期內完成驗證，您的帳戶將被永久凍結。</p>
        </body>
        </html>
        """
    },
    {
        "id": 3,
        "type": "中風險 (Medium Risk - 可疑地址)",
        "sender": "support@shipping-update.xiayue.tw",
        "subject": "包裹配送失敗通知，請確認您的收件地址",
        "body": """
        <html>
        <body>
            <p>您的包裹目前因地址資訊不完整，無法完成派送。</p>
            <p>請點擊下方連結更新您的配送地址，以便我們重新安排快遞發貨：</p>
            <p><a href="http://shorturl.at/xyz789">http://shorturl.at/xyz789</a></p>
            <br>
            <p>台灣宅配物流中心 敬上</p>
        </body>
        </html>
        """
    },
    {
        "id": 4,
        "type": "安全 (Low Risk)",
        "sender": "hr@xiayue.tw",
        "subject": "【重要通知】2026年第三季員工教育訓練課程報名開始",
        "body": """
        <html>
        <body>
            <p>各位同仁好，</p>
            <p>2026年第三季的「資訊安全防護與社交工程演練」課程已於今日開放報名。</p>
            <p>請全體員工於本月底前至內部 portal 選擇適合的時間場次參加。</p>
            <br>
            <p>人力資源處 敬啟</p>
        </body>
        </html>
        """
    },
    {
        "id": 5,
        "type": "高風險 (High Risk - 惡意執行檔)",
        "sender": "finance-dept@xiayue.tw",
        "subject": "Urgent: Q2 Employee Bonus list & payout scheme",
        "body": """
        <html>
        <body>
            <p>Dear all,</p>
            <p>The management team has approved the Q2 performance bonus distribution list. Please review the attached payout file to confirm your details.</p>
            <p>If there are any discrepancies, contact Finance before Friday.</p>
        </body>
        </html>
        """,
        "attachment_name": "Bonus_Payout_List_Q2.exe",
        "attachment_content": b"This is a simulated payload for a malicious executable file designed to test risk scanner detection."
    },
    {
        "id": 6,
        "type": "安全 (Low Risk)",
        "sender": "colleague-tim@xiayue.tw",
        "subject": "下週一專案進度討論會的會議紀錄",
        "body": """
        <html>
        <body>
            <p>各位好，這是今天專案同步會議的紀錄要點：</p>
            <ul>
                <li>前端 UI 開發進度達 90%。</li>
                <li>後端 API 完成安全過濾器設置。</li>
                <li>下週一下午 2 點召開整合測試審查會。</li>
            </ul>
            <p>謝謝大家！</p>
        </body>
        </html>
        """
    },
    {
        "id": 7,
        "type": "高風險 (High Risk - 偽造發信與 ReplyTo 異常)",
        "sender": "service@paypal.com.xiayue.tw",
        "reply_to": "hacker-mailbox@gmail.com",
        "subject": "Your payment of $799.00 USD to Steam Games was successful",
        "body": """
        <html>
        <body>
            <h2>PayPal Transaction Confirmation</h2>
            <p>Thank you for your purchase. We have authorized a payment of $799.00 USD to Steam Games from your account.</p>
            <p>If you did not authorize this transaction, please reply immediately or click the link below to cancel the transaction and claim a refund:</p>
            <p><a href="http://login-paypal-verify-account.xiayue.tw/dispute">Cancel Transaction & Refund</a></p>
        </body>
        </html>
        """
    },
    {
        "id": 8,
        "type": "中風險 (Medium Risk - 行銷與急迫性用詞)",
        "sender": "marketing@promo-sales.xiayue.tw",
        "subject": "🔥 僅限今日！全站商品 1 折起，限時特賣錯過不再！",
        "body": """
        <html>
        <body>
            <h3>🎉 超值限時大特賣！</h3>
            <p>親愛的會員，今日限時推出超殺特惠！多款熱銷商品下殺 1 折，數量有限，售完為止！</p>
            <p>現在立刻下單，輸入優惠碼 [HOT10] 即享免運優惠！</p>
        </body>
        </html>
        """
    },
    {
        "id": 9,
        "type": "安全 (Low Risk)",
        "sender": "system-notify@xiayue.tw",
        "subject": "[GitLab] Pipeline #109485 passed for branch 'main'",
        "body": """
        <html>
        <body>
            <p>GitLab CI/CD Pipeline Status:</p>
            <p><b>Project:</b> finalx-gmail-auto<br>
            <b>Branch:</b> main<br>
            <b>Commit:</b> d3b8a1c (Update unit tests)<br>
            <b>Status:</b> <span style="color: green; font-weight: bold;">PASSED</span></p>
        </body>
        </html>
        """
    },
    {
        "id": 10,
        "type": "高風險 (High Risk - 危險指令碼附件)",
        "sender": "it-support@xiayue.tw",
        "subject": "【緊急通知】請儘速執行系統安全性漏洞修補程式",
        "body": """
        <html>
        <body>
            <p>各位同仁好，</p>
            <p>資訊室接獲 Windows 系統重大漏洞通報。為防範勒索軟體攻擊，請所有人立即下載附件的修補指令碼並以系統管理員權限執行。</p>
            <p>感謝您的配合。</p>
            <br>
            <p>資訊安全處 敬啟</p>
        </body>
        </html>
        """,
        "attachment_name": "windows_patch_update.js",
        "attachment_content": b"// Simulated dangerous script for testing purpose\nconsole.log('Patching...');"
    }
]

WAVE_CONFIGS = {
    "1": {
        "name": "第一波：基本風險分布",
        "emails": TEST_EMAILS,
        "description": "4 封安全、2 封中風險、4 封高風險，適合做主要現場示範。",
    },
    "2": {
        "name": "第二波：進階釣魚與垃圾郵件情境",
        "emails": TEST_EMAILS_2,
        "description": "品牌仿冒、追蹤像素、雙重副檔名、勒索威脅、表單釣魚。",
    },
    "3": {
        "name": "第三波：社交工程與特殊攻擊情境",
        "emails": TEST_EMAILS_3,
        "description": "政府退稅、Unicode 混淆、巨集檔、MFA 釣魚、CEO 詐騙。",
    },
}

DEFAULT_INTERVAL_SECONDS = 2


def create_mime_message(sender, to, subject, body_html, reply_to=None, attachment_name=None, attachment_content=b""):
    message = MIMEMultipart()
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    if reply_to:
        message['reply-to'] = reply_to

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


def print_wave_list() -> None:
    print("可用測試波次：")
    for wave_id, config in WAVE_CONFIGS.items():
        emails = config["emails"]
        print(f"  {wave_id}) {config['name']} - {len(emails)} 封")
        print(f"     {config['description']}")


def resolve_target_email(service, override_to=None):
    if override_to:
        print(f"👉 目標收件匣顯示為: {override_to}")
        return override_to

    try:
        profile = service.users().getProfile(userId='me').execute()
        my_email = profile.get('emailAddress')
        print(f"👉 目標收件匣: {my_email}")
        return my_email
    except Exception:
        print("⚠️ 無法取得用戶 Email，將預設使用 'me' 作為收件者。")
        return "me"


def countdown(seconds):
    if seconds <= 0:
        return

    print(f"   ⏳ 等待 {seconds} 秒後發送下一封...")
    for sec in range(seconds, 0, -1):
        sys.stdout.write(f"\r      剩餘 {sec} 秒...")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r")
    sys.stdout.flush()


def print_mail_summary(position, total, mail):
    print(f"\n[{position}/{total}] 正在處理模板 #{mail['id']}...")
    print(f"   類型: {mail['type']}")
    print(f"   寄件者: {mail['sender']}")
    print(f"   主旨: {mail['subject']}")
    if mail.get("reply_to"):
        print(f"   Reply-To: {mail['reply_to']}")
    if mail.get("attachment_name"):
        print(f"   附件: {mail['attachment_name']}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="FINALX Gmail 10 封批次示範信插入工具",
    )
    parser.add_argument(
        "--wave",
        choices=sorted(WAVE_CONFIGS),
        default="1",
        help="選擇測試波次，預設 1。每波都是 10 封。",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        help=f"每封信插入間隔秒數，預設 {DEFAULT_INTERVAL_SECONDS}；現場快速展示可設 0。",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="插入前 N 封，預設 10。",
    )
    parser.add_argument(
        "--to",
        help="覆寫 MIME 郵件中的 To 欄位；不填則使用目前授權 Gmail 帳號。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只列出會插入的 10 封示範信，不連 Gmail、不寫入信箱。",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="列出三波測試情境後結束。",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.list:
        print_wave_list()
        return 0

    if args.limit <= 0:
        print("❌ --limit 必須大於 0。")
        return 2
    if args.interval < 0:
        print("❌ --interval 不能小於 0。")
        return 2

    config = WAVE_CONFIGS[args.wave]
    selected_emails = config["emails"][:args.limit]
    total = len(selected_emails)

    print("==================================================")
    print(f"      📧 FINALX Gmail 批次示範信插入：{config['name']}      ")
    print(f"      共 {total} 封 | 間隔 {args.interval} 秒 | 目前時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}      ")
    print("==================================================")
    print(config["description"])

    if args.dry_run:
        print("🧪 Dry-run 模式：只顯示模板，不會插入 Gmail。")
        my_email = args.to or "(目前授權 Gmail 帳號)"
        service = None
    else:
        try:
            service = build_gmail_service()
        except Exception as e:
            print(f"❌ 初始化 Gmail API 失敗: {e}")
            print("請確認是否已經產生 token.json 且憑證有效。")
            return 1
        my_email = resolve_target_email(service, args.to)

    print("\n安全分布設計：")
    print("🟢 安全信件：依波次內建模板")
    print("🟡 中風險信件：依波次內建模板")
    print("🔴 高風險信件：依波次內建模板")
    print("--------------------------------------------------")

    failures = 0

    for i, mail in enumerate(selected_emails, start=1):
        print_mail_summary(i, total, mail)

        if args.dry_run:
            print("   🧪 Dry-run：略過 Gmail 寫入。")
        else:
            msg_body = create_mime_message(
                sender=mail["sender"],
                to=my_email,
                subject=mail["subject"],
                body_html=mail["body"],
                reply_to=mail.get("reply_to"),
                attachment_name=mail.get("attachment_name"),
                attachment_content=mail.get("attachment_content", b"")
            )

            gmail_id = insert_message(service, msg_body)
            if gmail_id:
                print(f"   ✅ 成功插入！Gmail ID: {gmail_id}")
            else:
                failures += 1
                print("   ❌ 插入失敗。")

        if i < total:
            countdown(args.interval)

    print("\n==================================================")
    if args.dry_run:
        print(f"🧪 Dry-run 完成：{total} 封模板可用於示範。")
    elif failures:
        print(f"⚠️ 批次插入完成，但有 {failures} 封失敗。")
    else:
        print(f"🎉 {total} 封測試信件已全部插入完畢！")
    print("==================================================")
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(main())
