import re

SCAM_RULES = [
    {
        "reason": "Matches a common fake-job template from the dataset",
        "score": 30,
        "patterns": [
            r"\bdata entry complete training provided before you start\b",
            r"\bfull online training\b",
            r"\bpositions are still available\b",
            r"\bapply using below link\b",
            r"\bhome based payroll\b",
            r"\bwork area away from distractions\b",
            r"\binternet access\b",
            r"\bvalid email address\b",
            r"\bhonest self[- ]motivated\b",
            r"\bdata entry admin clerical\b",
            r"\bhome typing\b",
            r"\btypist\b",
        ],
    },
    {
        "reason": "Promises unusually easy remote earnings similar to known scam posts",
        "score": 25,
        "patterns": [
            r"\bearn (?:\$|rs\.?\s*)?\d{2,5}(?:\s*-\s*(?:\$|rs\.?\s*)?\d{2,5})?\s*(?:per day|daily|weekly)\b",
            r"\bearn much\b",
            r"\bextra per day\b",
            r"\bget started earn\b",
            r"\bwork from home and earn\b",
            r"\bonline training\b",
            r"\bno experience\b",
            r"\bno special skills\b",
        ],
    },
    {
        "reason": "Requests an upfront payment or fee",
        "score": 30,
        "patterns": [
            r"\bpay(?:ment)? fee\b",
            r"\bregistration fee\b",
            r"\bsecurity deposit\b",
            r"\bprocessing fee\b",
            r"\bapplication fee\b",
            r"\bpay upfront\b",
        ],
    },
    {
        "reason": "Uses high-pressure urgency language",
        "score": 15,
        "patterns": [
            r"\burgent hiring\b",
            r"\burgent staff wanted\b",
            r"\bjoin immediately\b",
            r"\bimmediate joining\b",
            r"\bapply now\b",
            r"\blimited slots\b",
        ],
    },
    {
        "reason": "Claims no interview or no screening is required",
        "score": 20,
        "patterns": [
            r"\bno interview\b",
            r"\bwithout interview\b",
            r"\bdirect selection\b",
            r"\binstant offer\b",
            r"\byou do not need any special skills\b",
        ],
    },
    {
        "reason": "Looks like a low-detail or title-only posting often seen in fraudulent rows",
        "score": 15,
        "patterns": [
            r"\bsales executive\s*$",
            r"\bforward cap\.?\s*$",
            r"\badmin clerical\b",
            r"\btemporary workers\b",
            r"\bopenings available\b",
        ],
    },
    {
        "reason": "Requests sensitive banking or identity details too early",
        "score": 15,
        "patterns": [
            r"\bbank account\b",
            r"\baadhaar\b",
            r"\bssn\b",
            r"\bdebit card\b",
            r"\bcredit card\b",
            r"\bupi pin\b",
        ],
    },
]


def _normalize_text(job_description="", job_url=""):
    return f"{job_description}\n{job_url}".strip().lower()


def _contains_repeated_short_text(text):
    normalized = re.sub(r"\s+", " ", text).strip()
    if not normalized:
        return False

    words = re.findall(r"[a-z0-9&']+", normalized)
    if len(words) <= 6 and len(set(words)) <= 3:
        return True

    return False


def _contains_hashed_contact_string(text):
    return re.search(r"\b[a-f0-9]{32,}\b", text, flags=re.IGNORECASE) is not None


def analyze_job_risk(job_description="", job_url="", additional_rules=None):
    text = _normalize_text(job_description, job_url)
    if not text:
        return {
            "risk_score": 0,
            "risk_level": "Low",
            "red_flags": [],
        }

    score = 0
    red_flags = []
    active_rules = list(SCAM_RULES)
    if additional_rules:
        active_rules.extend(additional_rules)

    for rule in active_rules:
        for pattern in rule["patterns"]:
            if re.search(pattern, text, flags=re.IGNORECASE):
                score += rule["score"]
                red_flags.append(rule["reason"])
                break

    if re.search(r"https?://(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy)", text, flags=re.IGNORECASE):
        score += 10
        red_flags.append("Uses a shortened URL that can hide the real destination")

    if re.search(r"\bwhatsapp\b|\btelegram\b", text, flags=re.IGNORECASE):
        score += 10
        red_flags.append("Pushes conversation to informal messaging channels")

    if _contains_hashed_contact_string(text):
        score += 15
        red_flags.append("Contains an obfuscated contact string often seen in suspicious scraped postings")

    if _contains_repeated_short_text(text):
        score += 10
        red_flags.append("The posting is extremely short or repetitive, which matches many low-detail scam samples")

    score = min(score, 100)

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_score": score,
        "risk_level": level,
        "red_flags": red_flags,
    }
