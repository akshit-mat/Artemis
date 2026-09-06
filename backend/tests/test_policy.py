from artemis.agent.policy import should_use_reasoning

def test_fast_greetings():
    assert should_use_reasoning("hi") is False
    assert should_use_reasoning("  HELLO  ") is False
    assert should_use_reasoning("Hey!") is False
    assert should_use_reasoning("good morning") is False
    assert should_use_reasoning("good night.") is False

def test_fast_acknowledgements():
    assert should_use_reasoning("thanks") is False
    assert should_use_reasoning("thank you!") is False
    assert should_use_reasoning("ok") is False
    assert should_use_reasoning("Okay.") is False
    assert should_use_reasoning("got it") is False
    assert should_use_reasoning("understood") is False
    assert should_use_reasoning("yes") is False
    assert should_use_reasoning("no") is False
    assert should_use_reasoning("yep") is False
    assert should_use_reasoning("nope") is False

def test_fast_pure_arithmetic():
    assert should_use_reasoning("2+2") is False
    assert should_use_reasoning(" 2 + 2 ") is False
    assert should_use_reasoning("15 * (4 + 3) = ?") is False
    assert should_use_reasoning("100 / 2.5 - 10") is False

def test_think_word_problems():
    # Contains letters, so it fails the pure arithmetic regex
    assert should_use_reasoning("A farmer has 17 sheep, and all but 9 die. How many are left?") is True
    assert should_use_reasoning("What is 15 apples minus 3 apples?") is True
    assert should_use_reasoning("If John has 5 apples and Mary has 2, how many in total?") is True

def test_think_complex_ambiguous_short_prompts():
    assert should_use_reasoning("Is P=NP?") is True
    assert should_use_reasoning("What?") is True
    assert should_use_reasoning("I don't know") is True
    assert should_use_reasoning("Why?") is True
    assert should_use_reasoning("tell me a story") is True

def test_think_complex_triggers_in_what_is():
    # Matches 'what is' but has a complex trigger
    assert should_use_reasoning("what is the difference between TCP and UDP?") is True
    assert should_use_reasoning("what is an explanation for gravity?") is True
    assert should_use_reasoning("who is the safest driver?") is True
    assert should_use_reasoning("what is the bug in this code?") is True
    assert should_use_reasoning("where is the error in my plan?") is True

def test_fast_trivial_what_is():
    # Safe simple lookups
    assert should_use_reasoning("what is the capital of Japan?") is False
    assert should_use_reasoning("who is Abraham Lincoln?") is False
    assert should_use_reasoning("where is the eiffel tower?") is False
    assert should_use_reasoning("what time is it in Tokyo?") is False
    assert should_use_reasoning("what's the speed of light?") is False

def test_think_coding_debugging():
    assert should_use_reasoning("Write a Python script to sort a list") is True
    assert should_use_reasoning("Fix this bug: IndexError") is True
    assert should_use_reasoning("def hello(): pass") is True
    assert should_use_reasoning("What is the best way to code a loop?") is True

def test_think_advice_recommendations():
    assert should_use_reasoning("what is the best car to buy?") is True
    assert should_use_reasoning("is it legal to copy software?") is True
    assert should_use_reasoning("what should I do for my headache?") is True
    assert should_use_reasoning("recommend a good book") is True

def test_boundary_whitespace_case_behavior():
    assert should_use_reasoning("   WHaT Is 2+2?   ") is False # Note: 'what is 2+2?' triggers the math rule or wh-lookup rule
    assert should_use_reasoning("\twhat is 2+2?\n") is False
    assert should_use_reasoning("   ") is True # Default
    assert should_use_reasoning("") is True

def test_unknown_inputs_default_to_think():
    assert should_use_reasoning("Hello world, how are you today?") is True
    assert should_use_reasoning("Translate 'apple' to French") is True
    assert should_use_reasoning("Generate a poem about the sea") is True
    assert should_use_reasoning("Summarize this text: ...") is True
