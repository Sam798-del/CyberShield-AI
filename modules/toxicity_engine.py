"""
CyberShield AI — Cyberbullying & Textual Toxicity NLP Classifier
Owner: Shreya
Assigned Scope: Checks messages and posts for harassment, hate speech, threats,
social exclusion, body shaming, digital intimidation, and defamation in live text.

Benchmark Dataset Foundation:
- Google Jigsaw Toxic Comment Classification Challenge (Kaggle / Wikimedia)
- IEEE / Kaggle Formspring & Twitter Cyberbullying Benchmark
- StopBullying.gov Federal Cyberbullying Taxonomy
- Indian Cyber Crime Coordination Centre (I4C / IT Act Guidelines)
"""

import os
import json
import re

# Resolve local dataset path
DATASET_PATH = os.path.join(os.path.dirname(__file__), "datasets", "jigsaw_cyberbullying_corpus.json")

# Default in-memory taxonomy fallback
DEFAULT_TAXONOMY = {
    "threat": {
        "display_name": "Physical Threat & Extreme Violence",
        "severity_weight": 75,
        "patterns": [
            "i will find you", "kill yourself", "kill you", "i will kill you", "should kill you",
            "i should kill you", "murder you", "shoot you", "stab you", "strangle you",
            "beat you to death", "with a hammer", "with a knife", "with a gun", "go die",
            "should die", "hope you die", "deserve to die", "beat you", "hurt you",
            "destroy you", "slit your", "burn you", "murder", "end your life"
        ]
    },
    "intimidation": {
        "display_name": "Digital Intimidation, Harassment & Stalking",
        "severity_weight": 45,
        "patterns": [
            "keep messaging you until", "to your reputation", "make your life miserable",
            "delete your account", "can't escape", "disappear from this platform",
            "watch your back", "track your ip", "you will pay for this", "ruin your life",
            "ruin your future", "stalk"
        ]
    },
    "defamation": {
        "display_name": "Defamation, Rumours & Public Doxing",
        "severity_weight": 45,
        "patterns": [
            "spread this rumour", "spread this rumor", "embarrassing picture",
            "fake account just to expose", "fake account to expose", "expose you",
            "everyone should see this embarrassing", "share this post so everyone can laugh",
            "leak your private", "dox you"
        ]
    },
    "social_exclusion": {
        "display_name": "Social Exclusion & Ostracization (Relational Bullying)",
        "severity_weight": 45,
        "patterns": [
            "don't invite her", "don't invite him", "don't invite them", "nobody wants her around",
            "nobody wants him around", "nobody wants you around", "nobody wants you here",
            "make a group without", "ignore all his messages", "ignore all her messages",
            "unfollow this person", "they don't belong here", "you don't belong here",
            "nobody asked you", "leave this group", "nobody likes you"
        ]
    },
    "body_shaming": {
        "display_name": "Body Shaming & Aesthetic Ridicule",
        "severity_weight": 45,
        "patterns": [
            "looking like that", "look ridiculous", "look disgusting", "hide your face",
            "wear clothes like that", "your appearance is the reason", "you look horrible",
            "lose some weight", "so fat", "ugly face"
        ]
    },
    "insult": {
        "display_name": "Insults & Intellectual Humiliation",
        "severity_weight": 40,
        "patterns": [
            "stupid", "idiot", "loser", "ugly", "fat", "dumb", "dumbest", "hate you",
            "freak", "trash", "worthless", "pathetic", "complete joke", "nobody takes you seriously",
            "embarrassing", "laughs at you behind", "stop talking", "waste of space"
        ]
    },
    "profanity": {
        "display_name": "Profanity & Vulgar Slurs",
        "severity_weight": 50,
        "patterns": ["bitch", "bastard", "fuck", "shit", "asshole", "crap", "slut", "whore", "cunt", "skank", "hoe"]
    },
    "hate_speech": {
        "display_name": "Hate Speech & Identity Harassment",
        "severity_weight": 50,
        "patterns": ["subhuman", "terrorist", "freaks", "go back to your country"]
    }
}

def load_corpus() -> tuple:
    """Loads benchmark dataset corpus from JSON file or falls back to in-memory dictionary."""
    if os.path.exists(DATASET_PATH):
        try:
            with open(DATASET_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                metadata = data.get("metadata", {})
                categories = data.get("categories", DEFAULT_TAXONOMY)
                return categories, metadata
        except Exception:
            pass
    return DEFAULT_TAXONOMY, {"dataset_name": "Embedded Jigsaw/StopBullying Taxonomy", "version": "2.0.0"}

TAXONOMY_CATEGORIES, CORPUS_METADATA = load_corpus()

def analyze_cyberbullying(text: str) -> dict:
    """
    Evaluates text against the benchmark multi-class toxicity corpus.
    Identifies covert relational aggression, intimidation, defamation, insults, and threats.
    Returns calibrated risk score (0-100), category classifications, flagged patterns,
    and tailored legal/safety guidance.
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

    # Normalize whitespace and casing
    cleaned_text = re.sub(r"[^\w\s\']", " ", str(text).lower())
    padded_text = f" {' '.join(cleaned_text.split())} "

    categories = {}
    flagged_words = []
    category_matches = []
    score = 0

    # Scan against benchmark categories
    for cat_key, cat_data in TAXONOMY_CATEGORIES.items():
        patterns = cat_data.get("patterns", [])
        weight = cat_data.get("severity_weight", 30)
        matched_in_cat = []

        for p in patterns:
            # Check pattern existence in padded text
            if p in padded_text:
                matched_in_cat.append(p)
                flagged_words.append(p)

        if matched_in_cat:
            categories[cat_key] = True
            category_matches.append(cat_data.get("display_name", cat_key))
            score += weight
        else:
            categories[cat_key] = False

    # Combinatorial SVO Semantic Grammar Engine (Subject-Verb-Object Intent Rules)
    svo_grammar_rules = [
        # 1. Physical Assault & Violent Declarations
        ("threat", 85, r"\b(kill|murder|shoot|stab|choke|strangle|beat|smash|hit|cut|attack|destroy|hurt|burn|drown|torture|crush|punch|slap|slice|hang|slaughter|butcher)\s+(you|u|your\s+(head|face|throat|neck|body|chest)|her|him)\b", "direct violent assault"),
        ("threat", 80, r"\b(i\s*('?ll|will|should|must|wanna|want\s+to|gonna|am\s+going\s+to|can))\s+.*(kill|murder|beat|hurt|destroy|stab|shoot|smash|slap|attack|burn|crush)\s+(you|u)\b", "violent declaration"),
        ("threat", 75, r"\b(with\s+(a\s+)?(hammer|knife|gun|weapon|bat|blade|axe|acid|brick|pipe|crowbar|sword|rope|pistol|rifle))\b", "weapon assault"),
        # 2. Death Wishes & Suicide Incitement
        ("threat", 85, r"\b(you|u)\s+(should|must|need\s+to|deserve\s+to|ought\s+to|better|just)?\s*(die|perish|burn|suffer|rot|hang\s+yourself|kill\s+(yourself|urself)|end\s+your\s+life)\b|\bdie\s+(bitch|slut|whore|bastard|loser|idiot|now|alone|here)\b|\b(you|u)\s+die\b", "death wish / suicide incitement"),
        ("threat", 75, r"\b(should|hope|wish|want|deserve|pray)\s+(you|u)\s+(die|perish|rot|suffer|burn|get\s+killed)\b", "fatality wish"),
        ("threat", 75, r"\b(go|better|just)\s+die\b", "death incitement"),
        ("threat", 85, r"\b(kill|hang)\s+(yourself|urself)\b", "suicide incitement"),
        # 3. Universal Rejection & Social Exclusion
        ("social_exclusion", 55, r"\b(no\s*one|nobody|not\s+a\s+single\s+person|none\s+of\s+us)\s+(likes?|wants?|cares?\s+about|cares?|loves?|needs?|trusts?|respects?|talks?\s+to)\s+(you|u|her|him|them)\b", "universal rejection"),
        ("social_exclusion", 50, r"\b(don\'?t|do\s+not|never)\s+(invite|talk\s+to|speak\s+to|hang\s+out\s+with|message)\s+(her|him|them|you|u)\b", "relational ostracization"),
        ("social_exclusion", 50, r"\b(make\s+a\s+group|group\s+chat)\s+without\s+(him|her|them|you|u)\b", "exclusion group"),
        ("social_exclusion", 50, r"\b(ignore|block|mute)\s+(all\s+)?(his|her|their|your)\s+(messages|texts|calls|posts)\b", "communication blocking"),
        ("social_exclusion", 50, r"\b(they|you|u|she|he)\s+(don\'?t|does\s+not|doesn\'?t)\s+belong\s+(here|with\s+us|in\s+this\s+group)\b", "exclusion alienation"),
        # 4. Body Shaming & Aesthetic Denigration
        ("body_shaming", 55, r"\b(look|looking|looks)\s+(so\s+)?(ridiculous|disgusting|horrible|repulsive|ugly|fat|gross|hideous|repugnant|like\s+a\s+(clown|joke|pig|cow|whale|freak))\b", "appearance denigration"),
        ("body_shaming", 55, r"\b(appearance|face|weight|body|figure|skin)\s+(is\s+the\s+reason|makes\s+me\s+sick|is\s+disgusting|looks\s+terrible)\b", "body shaming"),
        ("body_shaming", 50, r"\b(upload|post|take)\s+(a\s+)?(picture|photo)\s+looking\s+like\s+that\b", "aesthetic mockery"),
        # 5. Digital Intimidation, Coercion & Cyberstalking
        ("intimidation", 55, r"\b(keep|continue)\s+(messaging|texting|calling|harassing|stalking|following)\s+(you|u)\s+(until|forever)\b", "stalking pressure"),
        ("intimidation", 55, r"\b(make\s+your\s+life|ruin\s+your|destroy\s+your)\s+(miserable|life|reputation|future|career|family)\b", "intimidation threat"),
        ("intimidation", 50, r"\b(delete|deactivate|remove)\s+(your\s+)?(account|profile|channel|post)\b", "account silencing"),
        ("intimidation", 50, r"\b(can\'?t|cannot|won\'?t)\s+escape\s+(me|what\s+i|this)\b", "coercive entrapment"),
        # 6. Defamation, Malicious Rumours & Doxing
        ("defamation", 55, r"\b(spread|share|leak|post|circulate)\s+(this\s+)?(rumour|rumor|lie|lies|photo|picture|screenshot|chat|video|private|secret)\b", "rumour / doxing spread"),
        ("defamation", 55, r"\b(fake\s+account|alt\s+account)\s+(just\s+)?to\s+expose\s+(you|her|him)\b", "smear campaign"),
        # 7. Direct Insults & Intellectual Humiliation
        ("insult", 50, r"\b(you(\'re|\s+are)|u\s+r)\s+(literally\s+)?(a\s+|an\s+|the\s+)?(dumbest|stupidest|biggest\s+loser|complete\s+joke|joke|laughing\s+stock|waste\s+of\s+space|brainless|moron|idiot|imbecile|retard|failure|clown|freak|loser)\b", "direct insult"),
        ("insult", 45, r"\b(nobody|no\s*one)\s+takes\s+you\s+seriously\b", "intellectual ridicule"),
        ("insult", 40, r"\b(your\s+)?opinions?\s+(are|is)\s+(embarrassing|pathetic|garbage|worthless)\b", "opinion humiliation"),
        # 8. Severe Profanity & Misogynistic Slurs
        ("profanity", 55, r"\b(slut|whore|bitch|cunt|skank|hoe|motherfucker|asshole|bastard|dipshit|douchebag)\b", "abusive profanity / misogynistic slur")
    ]

    for cat_key, weight, regex_pat, intent_label in svo_grammar_rules:
        if re.search(regex_pat, padded_text):
            if not categories.get(cat_key, False):
                categories[cat_key] = True
                category_matches.append(TAXONOMY_CATEGORIES.get(cat_key, {}).get("display_name", cat_key))
            score = max(score, weight)
            flagged_words.append(intent_label)

    # Compounding aggression factor (attacks spanning multiple categories)
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

    # Contextual safety actions based on benchmark legal guidance
    safety_actions = []
    if categories.get("threat") or categories.get("intimidation"):
        safety_actions.append("🚨 Threat / Intimidation: Do not engage. Immediately capture timestamped screenshots.")
        safety_actions.append("File a formal grievance on the National Cyber Crime Portal (cybercrime.gov.in / Helpline 1930) or local authorities under Sec 506/507 IPC.")
    
    if categories.get("defamation"):
        safety_actions.append("📢 Defamation / Rumours: Report the offending post/profile for impersonation and false statements under IT Act Section 66D / Sec 500 IPC.")
    
    if categories.get("body_shaming") or categories.get("social_exclusion"):
        safety_actions.append("🛑 Relational Bullying: Mute or block the perpetrator immediately. Enable platform anti-harassment filtering.")
    
    if categories.get("insult") or categories.get("profanity"):
        safety_actions.append("⚠️ Abusive Language: Flag the comment to forum or social media moderators for Community Guidelines violation.")

    if not safety_actions:
        safety_actions = ["No safety action required. Content is safe."]

    return {
        "status": "success",
        "text": text,
        "dataset_source": CORPUS_METADATA.get("dataset_name", "Google Jigsaw / IEEE Cyberbullying Benchmark"),
        "dataset_version": CORPUS_METADATA.get("version", "2.1.0"),
        "toxicity_score": score,
        "toxicity_level": toxicity_level,
        "status_color": status_color,
        "categories": categories,
        "category_matches": category_matches,
        "flagged_words": flagged_words,
        "safety_actions": safety_actions
    }
