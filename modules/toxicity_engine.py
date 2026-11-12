"""
CyberShield AI — Cyberbullying & Textual Toxicity NLP Classifier
Owner: Shreya
Assigned Scope: Checks messages and posts for harassment, hate speech, threats, and profanity in live text
"""

INSULT_WORDS = ["stupid", "idiot", "loser", "ugly", "fat", "dumb", "hate you", "freak", "trash", "worthless", "pathetic"]
HARASS_WORDS = ["kill yourself", "die", "go die", "nobody likes you", "shut up", "get a life", "creep", "stalk", "leave forever"]
THREAT_WORDS = ["i will find you", "beat you", "hurt you", "destroy you", "track your ip", "expose you", "ruin your life"]
PROFANITY_WORDS = ["bitch", "bastard", "fuck", "shit", "asshole", "crap"]
HATE_SPEECH_WORDS = ["slur", "subhuman", "terrorist", "freaks"]

def analyze_cyberbullying(text: str) -> dict:
    """
    Analyzes live text, comments, or chat messages for multi-class toxic harassment,
    assigning category flags, toxicity score (0-100), and recommended safety actions.
    """
    if not text or not text.strip():
        return {
            "status": "error",
            "message": "Input text cannot be empty",
            "toxicity_score": 0,
            "toxicity_level": "UNKNOWN"
        }

    t_lower = text.lower().strip()
    categories = {
        "insult": False,
        "harassment": False,
        "threat": False,
        "profanity": False,
        "hate_speech": False
    }
    flagged_words = []
    score = 0

    for w in INSULT_WORDS:
        if w in t_lower:
            categories["insult"] = True
            flagged_words.append(w)
            score += 25

    for w in HARASS_WORDS:
        if w in t_lower:
            categories["harassment"] = True
            flagged_words.append(w)
            score += 40

    for w in THREAT_WORDS:
        if w in t_lower:
            categories["threat"] = True
            flagged_words.append(w)
            score += 50

    for w in PROFANITY_WORDS:
        if w in t_lower:
            categories["profanity"] = True
            flagged_words.append(w)
            score += 15

    for w in HATE_SPEECH_WORDS:
        if w in t_lower:
            categories["hate_speech"] = True
            flagged_words.append(w)
            score += 45

    score = min(score, 100)
    flagged_words = list(set(flagged_words))

    if score >= 70:
        toxicity_level = "HIGHLY TOXIC / SEVERE HARASSMENT"
        status_color = "danger"
    elif score >= 35:
        toxicity_level = "MODERATE TOXICITY DETECTED"
        status_color = "warning"
    else:
        toxicity_level = "SAFE / NON-TOXIC CONTENT"
        status_color = "success"

    safety_actions = [
        "Block the sender on social media or messaging platforms.",
        "Capture screenshot evidence for documentation.",
        "Report the offensive message to platform moderators.",
        "Reach out to trusted cyber safety authorities or school counselor."
    ] if score >= 35 else ["No safety action required. Content is safe."]

    return {
        "status": "success",
        "text": text,
        "toxicity_score": score,
        "toxicity_level": toxicity_level,
        "status_color": status_color,
        "categories": categories,
        "flagged_words": flagged_words,
        "safety_actions": safety_actions
    }
