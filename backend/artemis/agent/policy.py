import re

def should_use_reasoning(prompt: str) -> bool:
    """
    Determines whether the agent should use reasoning (think=True) or fast mode (think=False).
    Returns True (THINK) by default, or False (FAST) if the prompt exactly matches
    one of the safe allowlists.
    """
    if not prompt:
        return True

    p = prompt.strip().lower()

    # Rule 1: Explicit greetings/acknowledgements
    fast_greetings = {
        "hi", "hello", "hey", "thanks", "thank you", "ok", "okay",
        "good morning", "good night", "got it", "understood", "yes", "no", "yep", "nope"
    }
    # Remove punctuation for matching greetings
    p_no_punct = re.sub(r'[^\w\s]', '', p).strip()
    if p_no_punct in fast_greetings:
        return False

    # Rule 2: Pure simple arithmetic expressions
    # Only allow digits, basic operators (+, -, *, /, ^), parentheses, equals, decimals, spaces, and optionally a question mark at the end
    # Prevent word problems (no letters)
    if re.match(r'^[\d\+\-\*\/\^\(\)\.\=\s]+\??$', p):
        return False

    # Rule 3: Narrow class of obviously trivial factual lookups
    # Starts with specific wh-prefixes
    is_wh_lookup = (
        p.startswith("what is ") or 
        p.startswith("what's ") or 
        p.startswith("who is ") or 
        p.startswith("who's ") or 
        p.startswith("where is ") or 
        p.startswith("where's ") or
        p.startswith("what time ")
    )
    if is_wh_lookup:
        complex_triggers = [
            "why", "how", "compar", "differenc", "explain", "explan", 
            "safe", "recommend", "legal", "medic", "financ", "plan", 
            "code", "bug", "error", "fix", "solve", "ambigu", 
            "best", "worst", "should", "buy", "minus", "plus", "times", "divid", "if"
        ]
        pattern = r'\b(' + '|'.join(complex_triggers) + r')'
        if not re.search(pattern, p):
            return False

    # Everything else defaults to THINK
    return True
