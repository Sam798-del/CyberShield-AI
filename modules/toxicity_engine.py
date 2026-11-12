"""
CyberShield AI — Cyberbullying & Textual Toxicity NLP Classifier
Owner: Shreya
Assigned Scope: Checks messages and posts for harassment, hate speech, threats,
social exclusion, body shaming, digital intimidation, and defamation in live text.
Taxonomy Reference: UNICEF & StopBullying.gov Cyberbullying Taxonomy + Indian Cyber Crime Guidelines (I4C/IT Act).
"""

import re

# 1. Insults & Direct Humiliation (Intellect, Worth, Mockery)
INSULT_PATTERNS = [
    "stupid", "idiot", "loser", "ugly", "fat", "dumb", "dumbest", "hate you", 
    "freak", "trash", "worthless", "pathetic", "complete joke", "nobody takes you seriously",
    "embarrassing", "laughs at you behind", "stop talking", "waste of space", "brainless",
    "fool", "incompetent", "clown", "good for nothing"
]

# 2. Social Exclusion & Ostracization (Relational Aggression, Gatekeeping)
SOCIAL_EXCLUSION_PATTERNS = [
    "don't invite her", "don't invite him", "don't invite them", "nobody wants her around",
    "nobody wants him around", "nobody wants you around", "nobody wants you here",
    "make a group without", "ignore all his messages", "ignore all her messages",
    "ignore all their messages", "unfollow this person", "they don't belong here",
    "you don't belong here", "nobody asked you", "leave this group", "get out of here",
    "kick him out", "kick her out", "nobody cares about you", "nobody likes you",
    "leave us alone", "you are not welcome"
]

# 3. Body Shaming & Aesthetic Ridicule
BODY_SHAMING_PATTERNS = [
    "looking like that", "look ridiculous", "look disgusting", "hide your face",
    "wear clothes like that", "your appearance is the reason", "you look horrible",
    "lose some weight", "so fat", "so skinny", "ugly face", "gross body",
    "nobody wants to see your face", "dressing like a", "you look like a joke"
]

# 4. Digital Intimidation, Harassment & Stalking
INTIMIDATION_PATTERNS = [
    "keep messaging you until", "to your reputation", "make your life miserable",
    "delete your account", "can't escape", "disappear from this platform",
    "i'll make your life miserable", "i will make your life miserable",
    "watch your back", "track your ip", "you will pay for this",
    "you're going to regret this", "you are going to regret this",
    "ruin your life", "ruin your future", "hunt you down", "stalk"
]

# 5. Defamation, Rumours & Doxing (Public Shaming, Fake Accounts)
DEFAMATION_PATTERNS = [
    "spread this rumour", "spread this rumor", "embarrassing picture",
    "fake account just to expose", "fake account to expose", "expose you",
    "everyone should see this embarrassing", "share this post so everyone can laugh",
    "spread lies about", "ruin his reputation", "ruin her reputation",
    "leak your private", "post your secrets", "dox you", "expose your chats"
]

# 6. Physical Threats & Extreme Violence
THREAT_PATTERNS = [
    "i will find you", "kill yourself", "go die", "beat you", "hurt you",
    "destroy you", "slit your", "burn you", "murder", "end your life",
    "physically hurt you", "smash your"
]

# 7. Profanity & Vulgar Slurs
PROFANITY_PATTERNS = [
    "bitch", "bastard", "fuck", "shit", "asshole", "crap", "dick", "cunt",
    "douchebag", "prick"
]

# 8. Hate Speech & Identity Bias (Race, Religion, Gender, Caste)
HATE_SPEECH_PATTERNS = [
    "slur", "subhuman", "terrorist", "freaks", "go back to your country",
    "worthless caste", "dirty immigrant"
]

def analyze_cyberbullying(text: str) -> dict:
    """
    Analyzes live text, comments, or chat messages for multi-class cyberbullying
    including covert relational aggression (social exclusion, body shaming, defamation, intimidation).
    Returns category flags, 0-100 toxicity score, severity classification, and specific safety advice.
    """
    if not text or not str(text).strip():
        return {
            "status": "error",
            "message": "Input text cannot be empty",
            "toxicity_score": 0,
            "toxicity_level": "UNKNOWN",
            "categories": {},
            "flagged_words": [],
            "safety_actions": ["No input provided."]
        }

    t_lower = " " + text.lower().strip() + " "
    
    categories = {
        "insult": False,
        "social_exclusion": False,
        "body_shaming": False,
        "intimidation": False,
        "defamation": False,
        "threat": False,
        "profanity": False,
        "hate_speech": False
    }
    
    flagged_words = []
    category_matches = []
    score = 0

    # Helper scanner
    def match_patterns(patterns, cat_name, base_weight):
        nonlocal score
        found = False
        for p in patterns:
            # Word boundary / substring check
            if p in t_lower:
                found = True
                flagged_words.append(p)
        if found:
            categories[cat_name] = True
            category_matches.append(cat_name)
            score += base_weight

    # 1. Threats (Severe - immediate high risk)
    match_patterns(THREAT_PATTERNS, "threat", 60)

    # 2. Hate speech (Severe)
    match_patterns(HATE_SPEECH_PATTERNS, "hate_speech", 50)

    # 3. Digital Intimidation & Harassment
    match_patterns(INTIMIDATION_PATTERNS, "intimidation", 45)

    # 4. Defamation, Rumours & Doxing
    match_patterns(DEFAMATION_PATTERNS, "defamation", 45)

    # 5. Social Exclusion & Ostracization
    match_patterns(SOCIAL_EXCLUSION_PATTERNS, "social_exclusion", 45)

    # 6. Body Shaming
    match_patterns(BODY_SHAMING_PATTERNS, "body_shaming", 45)

    # 7. Insults & Humiliation
    match_patterns(INSULT_PATTERNS, "insult", 40)

    # 8. Profanity
    match_patterns(PROFANITY_PATTERNS, "profanity", 25)

    # Multi-category compounding factor (compound aggression)
    if len(category_matches) > 1:
        score += (len(category_matches) - 1) * 15

    score = min(score, 100)
    flagged_words = list(set(flagged_words))

    # Determine Severity Level
    if score >= 65:
        toxicity_level = "HIGHLY TOXIC / SEVERE HARASSMENT"
        status_color = "danger"
    elif score >= 35:
        toxicity_level = "MODERATE TOXICITY DETECTED"
        status_color = "warning"
    else:
        toxicity_level = "SAFE / NON-TOXIC CONTENT"
        status_color = "success"

    # Contextual safety guidance based on detected categories
    safety_actions = []
    if categories["threat"] or categories["intimidation"]:
        safety_actions.append("🚨 Threat / Intimidation: Do not engage. Immediately capture timestamped screenshots and report to platform security.")
        safety_actions.append("File a formal grievance on the National Cyber Crime Portal (cybercrime.gov.in / Dial 1930) or local authorities.")
    
    if categories["defamation"]:
        safety_actions.append("📢 Defamation / Rumours: Report the offending post/profile for impersonation and false statements under IT Act Section 66D / 500 IPC.")
    
    if categories["body_shaming"] or categories["social_exclusion"]:
        safety_actions.append("🛑 Relational Bullying: Mute or block the perpetrator immediately. Enable platform anti-harassment filtering.")
    
    if categories["insult"] or categories["profanity"]:
        safety_actions.append("⚠️ Abusive Language: Flag the comment to forum or social media moderators for Community Guidelines violation.")

    if not safety_actions:
        safety_actions = ["No safety action required. Content is safe."]

    return {
        "status": "success",
        "text": text,
        "toxicity_score": score,
        "toxicity_level": toxicity_level,
        "status_color": status_color,
        "categories": categories,
        "category_matches": category_matches,
        "flagged_words": flagged_words,
        "safety_actions": safety_actions
    }
