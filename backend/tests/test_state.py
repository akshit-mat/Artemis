from artemis.agent.state import AssistantStateCompute

def test_assistant_state_precedence():
    comp = AssistantStateCompute()

    assert comp.compute()["state"] == "IDLE"

    comp.set_state("run1", "THINKING")
    assert comp.compute()["state"] == "THINKING"

    comp.set_state("run2", "EXECUTING")
    assert comp.compute()["state"] == "EXECUTING"

    # Offline beats executing
    comp.set_state("sys", "OFFLINE")
    assert comp.compute()["state"] == "OFFLINE"

    # Remove offline
    comp.clear_state("sys")
    assert comp.compute()["state"] == "EXECUTING"

    # Error beats executing
    comp.set_state("err", "ERROR")
    assert comp.compute()["state"] == "ERROR"

    # Clear all
    comp.clear_state("run1")
    comp.clear_state("run2")
    comp.clear_state("err")
    assert comp.compute()["state"] == "IDLE"
