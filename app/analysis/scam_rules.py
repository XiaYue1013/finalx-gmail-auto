from __future__ import annotations

import re
from dataclasses import dataclass

from app.models import ScamRuleHit


@dataclass(frozen=True)
class ScamRule:
    rule_id: str
    name: str
    category: str
    severity: str
    score_delta: int
    pattern: re.Pattern[str]
    explanation: str


RULES: tuple[ScamRule, ...] = (
    ScamRule(
        "urgency_pressure",
        "限時壓迫話術",
        "social_engineering",
        "high",
        12,
        re.compile(r"(立即|立刻|馬上|限時|最後通知|逾期|倒數|今天內|24小時|否則|即將停用|即將凍結|永久註銷|限制功能|限制使用|immediately|urgent|final notice|within 24 hours|suspended)", re.IGNORECASE),
        "信件使用急迫期限或停權威脅，常見於釣魚與詐騙郵件。",
    ),
    ScamRule(
        "otp_request",
        "要求提供 OTP 或驗證碼",
        "credential_theft",
        "critical",
        28,
        re.compile(r"(OTP|one[-\s]?time password|verification code|一次性密碼|驗證碼|簡訊碼|認證碼|動態密碼).{0,32}(提供|回覆|輸入|告知|傳送|reply|send|enter|confirm)", re.IGNORECASE),
        "要求提供驗證碼通常是帳號盜用或付款詐騙的高風險訊號。",
    ),
    ScamRule(
        "bank_account_abnormal",
        "假銀行或帳戶異常",
        "phishing",
        "high",
        18,
        re.compile(r"(帳戶|帳號|銀行|信用卡|網銀|金融卡|系統|account|bank|credit card|wallet).{0,32}(異常|凍結|停用|驗證|升級|安全確認|重新登入|虛擬用戶|verify|verification|locked|limited|suspended|upgrade)", re.IGNORECASE),
        "假冒銀行或系統要求驗證帳戶是常見釣魚手法。",
    ),
    ScamRule(
        "account_takeover_alert",
        "帳號接管警示釣魚",
        "credential_theft",
        "critical",
        36,
        re.compile(
            r"((unauthorized|unrecogni[sz]ed|suspicious).{0,64}(password change|login|ip address|device|attempt)|"
            r"(password change attempt|change your .*password).{0,80}(secure|verify|login|account))",
            re.IGNORECASE,
        ),
        "冒用帳號異常或密碼變更警示，誘導使用者進入登入或驗證頁，是高風險帳密竊取情境。",
    ),
    ScamRule(
        "parcel_delivery",
        "假包裹或物流通知",
        "delivery_scam",
        "medium",
        16,
        re.compile(
            r"(包裹|物流|宅配|快遞|郵局|海關|運費|清關|配送|投遞|收件資訊|收件地址|parcel|delivery|shipment|customs)"
            r".{0,60}"
            r"(補繳|補款|重新配送|配送失敗|投遞失敗|無法配送|無法投遞|地址錯誤|地址不完整|"
            r"更新地址|更新收件|確認收件|重新確認|收件資訊|包裹領取|領取包裹|取件|未送達|卡關|手續費|"
            r"pay|payment|reschedule|address|held|failed)",
            re.IGNORECASE,
        ),
        "假包裹通知常誘導使用者點擊付款或登入連結。",
    ),
    ScamRule(
        "government_refund_phishing",
        "政府退稅領款釣魚",
        "payment_scam",
        "critical",
        36,
        re.compile(
            r"(\btax\b|\brefund\b|\birs\b|\bgovernment\b|財政部|國稅局|退稅|所得稅|繳稅)"
            r".{0,120}(claim|bank account|wire|payment|領取|銀行帳戶|匯款|款項|申領)",
            re.IGNORECASE,
        ),
        "冒用政府或稅務服務要求領退稅、填銀行帳戶或進入指定網站，是高風險釣魚與個資詐騙。",
    ),
    ScamRule(
        "investment_guarantee",
        "保證獲利投資話術",
        "investment_scam",
        "high",
        20,
        re.compile(r"(保證獲利|穩賺不賠|內線|老師帶單|高報酬|日收益|月收益|翻倍|入金|出金|投資群|guaranteed profit|risk[-\s]?free|double your money|crypto investment)", re.IGNORECASE),
        "保證獲利與帶單群組是常見投資詐騙特徵。",
    ),
    ScamRule(
        "prize_claim_personal_info",
        "中獎領獎個資誘導",
        "social_engineering",
        "medium",
        28,
        re.compile(
            r"(congratulations|you won|winner|grand prize|lucky user|randomly selected|中獎|得獎|抽中|幸運用戶)"
            r".{0,120}(claim|reward|register|shipping details|領取|登記|收件資料|寄送資料)",
            re.IGNORECASE,
        ),
        "中獎或抽獎通知要求領獎、註冊或填寫收件資料，常見於個資蒐集與假活動詐騙。",
    ),
    ScamRule(
        "discount_purchase_lure",
        "折扣促銷導購誘導",
        "social_engineering",
        "medium",
        18,
        re.compile(
            r"(\d{1,2}%\s*off|discount|limited time|promo code|special offer|半價|折扣|限時|優惠碼)"
            r".{0,100}(buy|checkout|order|software|license|購買|下單|結帳)",
            re.IGNORECASE,
        ),
        "大幅折扣、限時優惠與導購連結搭配出現時，常見於行銷垃圾信與假促銷頁。",
    ),
    ScamRule(
        "celebrity_giveaway_impersonation",
        "假名人抽獎或福利導流",
        "impersonation",
        "high",
        24,
        re.compile(
            r"(mrbeast|elonmusk|youtube|youtuber|名人|網紅|官方).{0,80}"
            r"(giveaway|bonus|activatecode|claim|free|gift|抽獎|福利|獎金|領取)",
            re.IGNORECASE,
        ),
        "假冒名人或官方帳號搭配抽獎、福利、獎金領取，常用來導向詐騙網站。",
    ),
    ScamRule(
        "crypto_casino_withdrawal",
        "加密貨幣賭場或出金誘導",
        "payment_scam",
        "high",
        28,
        re.compile(
            r"((usdt|crypto|casino|rakeback|賭場|加密貨幣).{0,100}"
            r"(withdraw|withdrawal|deposit|claimed|activate|bonus|profit|提款|入金|出金|成功|獲利|收益)|"
            r"(withdrawal\s*success|提款成功|出金成功|成功出金|成功提領).{0,80}"
            r"(usdt|crypto|casino|bonus|profit|claimed|賭場|獲利|收益))",
            re.IGNORECASE,
        ),
        "加密貨幣、賭場、獎金與出金成功畫面同時出現時，常見於假投資或假博弈詐騙素材。",
    ),
    ScamRule(
        "crypto_airdrop_wallet_connect",
        "加密貨幣空投錢包連結誘導",
        "investment_scam",
        "medium",
        28,
        re.compile(
            r"(airdrop|solana|phantom|metamask|web3|wallet|空投|錢包)"
            r".{0,120}(connect|claim|active wallet|領取|連結|連接)",
            re.IGNORECASE,
        ),
        "空投或代幣活動要求連接錢包領取獎勵，常見於錢包授權與資產竊取詐騙。",
    ),
    ScamRule(
        "ransomware_extortion",
        "勒索軟體付款威脅",
        "payment_scam",
        "critical",
        40,
        re.compile(
            r"(ransomware|files are encrypted|databases have been encrypted|decrypt|encrypted by ransomware|勒索|檔案已加密)"
            r".{0,160}(pay|btc|bitcoin|release your private|decrypt|付款|比特幣|公開資料)",
            re.IGNORECASE,
        ),
        "宣稱檔案遭加密並要求以加密貨幣付款，是典型勒索軟體或恐嚇詐騙。",
    ),
    ScamRule(
        "mfa_reauth_phishing",
        "MFA 重新驗證釣魚",
        "credential_theft",
        "critical",
        36,
        re.compile(
            r"(mfa|multi[-\s]?factor|office\s*365|outlook|authenticator|re-authenticate|re-validate|二次驗證|多因素)"
            r".{0,140}(suspension|login|verify|re-authenticate|re-validate|驗證|登入|停用|暫停)",
            re.IGNORECASE,
        ),
        "假冒 MFA 或企業帳號重新驗證，誘導登入或驗證，是高風險帳號接管釣魚。",
    ),
    ScamRule(
        "business_email_compromise_wire",
        "商務電郵匯款詐騙",
        "payment_scam",
        "critical",
        36,
        re.compile(
            r"(ceo|board meeting|confidential|acquisition|escrow|urgent request|執行長|董事會|機密|收購)"
            r".{0,220}(wire transfer|bank account|payment|transfer|匯款|轉帳|付款|escrow)|"
            r"(wire transfer|bank account|escrow|匯款|轉帳).{0,220}(ceo|board meeting|confidential|acquisition|urgent request|執行長|董事會|機密|收購)",
            re.IGNORECASE,
        ),
        "冒用主管或商務情境要求緊急匯款，是典型 BEC 社交工程詐騙。",
    ),
    ScamRule(
        "remote_job_telegram_lure",
        "遠端高薪工作導流",
        "employment_scam",
        "medium",
        28,
        re.compile(
            r"(work from home|remote online|part[-\s]?time|earn up to|weekly payouts|no experience|在家工作|兼職|高薪)"
            r".{0,140}(telegram|hiring manager|contact recruiter|recruiter|應徵|招聘|聯絡)",
            re.IGNORECASE,
        ),
        "高薪遠端兼職搭配即時通訊聯絡，常見於假求職、刷單或個資蒐集詐騙。",
    ),
    ScamRule(
        "fake_profit_proof",
        "出金成功或獲利截圖證明",
        "investment_scam",
        "medium",
        18,
        re.compile(
            r"(withdrawalsuccess|profit|claimed|出金成功|提款成功|成功出金|成功提領|獲利|收益|"
            r"\$\d[\d,]*(?:\.\d{1,2})?.{0,24}(profit|claimed|withdraw|withdrawal|獲利|收益|出金|提款))",
            re.IGNORECASE,
        ),
        "用出金成功、獲利或已領取畫面當作可信度證明，是投資與博弈詐騙常見包裝。",
    ),
    ScamRule(
        "bonus_code_lure",
        "獎金代碼或福利領取誘導",
        "social_engineering",
        "medium",
        14,
        re.compile(
            r"(activatecode.{0,50}bonus|bonus.{0,50}activatecode|bonuscode|promocode|claimbonus|"
            r"(bonus|獎金|福利).{0,50}(claim|receive|activate|code|領取|啟用|代碼))",
            re.IGNORECASE,
        ),
        "要求啟用代碼、領取 bonus 或福利，是假活動與博弈導流常見誘餌。",
    ),
    ScamRule(
        "payment_request",
        "要求轉帳或支付費用",
        "payment_scam",
        "high",
        18,
        re.compile(
            r"((請|需|需要|必須|請於|立即|前往|完成|補繳|支付|繳納).{0,32}"
            r"(轉帳|匯款|付款|繳費|手續費|保證金|解凍金|認證金|入金)|"
            r"(轉帳|匯款|付款|繳費|手續費|保證金|解凍金|認證金|入金).{0,32}"
            r"(帳號|銀行|ATM|超商|點數|錢包|USDT|指定|連結|網址)|"
            r"wire transfer|bank transfer|processing fee|payment required|make a payment|pay the fee)",
            re.IGNORECASE,
        ),
        "要求使用者轉帳、繳費或支付保證金時需要高度警覺。",
    ),
    ScamRule(
        "subscription_billing_phishing",
        "訂閱付款資訊更新釣魚",
        "phishing",
        "high",
        24,
        re.compile(
            r"(netflix|paypal|apple|microsoft|subscription|billing|membership|訂閱|續費|會員)"
            r".{0,140}"
            r"(update|verify|payment method|billing information|credit card|avoid account suspension|termination|"
            r"更新付款|付款資訊|信用卡|避免停用|終止服務|暫停)",
            re.IGNORECASE,
        ),
        "假冒訂閱或付款失敗通知要求更新付款資訊，常導向信用卡或帳號釣魚頁。",
    ),
    ScamRule(
        "credential_login",
        "要求重新登入或驗證身份",
        "phishing",
        "high",
        16,
        re.compile(r"(重新登入|登入驗證|身份驗證|帳號驗證|完成驗證|密碼確認|安全中心|解除限制|恢復使用|自助機器人|verify your identity|confirm your identity|update your password|reset your password|login verification|security center)", re.IGNORECASE),
        "要求重新登入或驗證的連結可能導向仿冒網站竊取帳密。",
    ),
    ScamRule(
        "fake_support",
        "假客服導流",
        "support_scam",
        "medium",
        10,
        re.compile(r"(客服|專員|助理|經理|support|agent).{0,24}(加line|加入LINE|私訊|telegram|聯繫|協助處理|contact us|chat|whatsapp)", re.IGNORECASE),
        "導流到私人客服帳號常見於投資、購物與帳戶處理詐騙。",
    ),
    ScamRule(
        "law_enforcement_impersonation",
        "假檢警或司法威脅",
        "impersonation",
        "critical",
        26,
        re.compile(
            r"((檢警|警察|法院|地檢署|刑事局|司法機關|police|court|law enforcement)"
            r".{0,80}(洗錢|通緝|偵查|筆錄|監管帳戶|安全帳戶|轉帳|匯款|money laundering|arrest warrant)|"
            r"(監管帳戶|安全帳戶).{0,40}(轉帳|匯款|資金))",
            re.IGNORECASE,
        ),
        "假冒檢警或司法機關要求配合轉帳，是高風險詐騙模式。",
    ),
    ScamRule(
        "social_account_phishing",
        "通訊或社群帳號凍結騙局",
        "phishing",
        "critical",
        40,
        re.compile(r"(telegram|line|wechat|whatsapp|臉書|facebook|ig|instagram|gmail|google|帳戶|帳號|account).{0,70}(異常|凍結|限制|註銷|封號|虛擬用戶|locked|limited|suspended|disabled).{0,70}(自助機器人|客服|驗證|登入|解除|verify|login|restore)", re.IGNORECASE),
        "官方服務通常不會透過非官方連結要求驗證以解除帳號限制，這是高風險盜號釣魚手法。",
    ),
    ScamRule(
        "dangerous_attachment_lure",
        "高風險附件誘導",
        "malware",
        "high",
        24,
        re.compile(
            r"("
            r"(?:invoice|receipt|statement|contract|attachment).{0,48}(?:open|download|enable macro)|"
            r"(?:合約|對帳單|附件|附檔|檔案).{0,48}(?:啟用巨集|下載|打開|開啟|查看)|"
            r"(?:發票|收據).{0,48}(?:附件|附檔|檔案).{0,48}(?:啟用巨集|下載|打開|開啟|查看)"
            r")",
            re.IGNORECASE,
        ),
        "以發票、收據、對帳單或合約誘導開啟附件，是惡意郵件常見手法。",
    ),
)


class ScamRuleEngine:
    def match(self, text: str) -> list[ScamRuleHit]:
        candidates = self._match_candidates(text)
        hits: list[ScamRuleHit] = []
        for rule in RULES:
            match = None
            for candidate in candidates:
                match = rule.pattern.search(candidate)
                if match is not None:
                    break
            if match is None:
                continue
            hits.append(
                ScamRuleHit(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    category=rule.category,
                    severity=rule.severity,  # type: ignore[arg-type]
                    score_delta=rule.score_delta,
                    matched_text=match.group(0)[:120],
                    explanation=rule.explanation,
                )
            )
        return hits

    def _match_candidates(self, text: str) -> tuple[str, ...]:
        raw = (text or "").lower()
        normalized = " ".join(raw.split())
        compact = re.sub(r"\s+", "", raw)
        no_bracket_tags = re.sub(r"\[[^\]]{1,40}\]", "", raw)
        deobfuscated = re.sub(r"[^0-9a-z\u4e00-\u9fff@._:/-]+", "", no_bracket_tags)
        return tuple(dict.fromkeys(candidate for candidate in (compact, normalized, deobfuscated) if candidate))
