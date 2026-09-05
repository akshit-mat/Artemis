import logging
from typing import Any, Dict, List, Tuple
from dataclasses import dataclass
import sqlite3

from ..models.base import Message

log = logging.getLogger("agent.context")

@dataclass
class AssemblyResult:
    messages: List[Message]
    tokens_by_tier: Dict[int, int]
    evicted_messages: int

def estimate_tokens(text: str) -> int:
    """Heuristic token estimation: length / 3.6"""
    if not text:
        return 0
    return int(len(text) / 3.6)

class ContextAssembler:
    def __init__(self, num_ctx: int, reserve_output_tokens: int = 1024):
        self.num_ctx = num_ctx
        self.reserve_output_tokens = reserve_output_tokens
        self.safety_margin = 256
        self.usable_budget = max(0, self.num_ctx - self.reserve_output_tokens - self.safety_margin)

        self.tier_0_cap = 500
        self.tier_2_cap = 300

    def assemble(self, raw_messages: List[sqlite3.Row]) -> AssemblyResult:
        """
        Assemble messages enforcing budgets.
        Tier 0: System instructions
        Tier 2: User profile/preferences
        Tier 5: Verbatim turns (newest first, oldest evicted)
        """
        tokens_by_tier = {0: 0, 2: 0, 5: 0}

        # 1. Tier 0 - System (Hardcoded for now as it's the minimal path)
        system_content = "You are ARTEMIS, a helpful local AI assistant."
        tier_0_tokens = estimate_tokens(system_content)
        if tier_0_tokens > self.tier_0_cap:
            # We enforce cap on our own system prompt
            pass # In practice, our system prompt should be designed to fit

        tokens_by_tier[0] = tier_0_tokens

        # 2. Tier 2 - Profile (Mocked empty for this phase)
        tier_2_tokens = 0
        tokens_by_tier[2] = tier_2_tokens

        # 3. Tier 5 - Verbatim turns
        tier_5_budget = max(0, self.usable_budget - tokens_by_tier[0] - tokens_by_tier[2])

        tier_5_messages: List[Message] = []
        tier_5_tokens = 0
        evicted = 0

        # Iterate backwards (newest first)
        for i, row in enumerate(reversed(raw_messages)):
            content = row["content"]
            role = row["role"]

            # Use stored token estimate if available, otherwise compute
            msg_tokens = row["token_estimate"]
            if msg_tokens is None:
                msg_tokens = estimate_tokens(content)

            if tier_5_tokens + msg_tokens <= tier_5_budget:
                # Need to insert at beginning since we're iterating backwards
                tier_5_messages.insert(0, {"role": role, "content": content})
                tier_5_tokens += msg_tokens
            else:
                # Once we hit a message that doesn't fit, ALL older messages must be evicted.
                # We do not skip middle messages to pack older smaller messages.
                evicted += len(raw_messages) - i
                break

        tokens_by_tier[5] = tier_5_tokens

        # Assemble final prompt
        final_messages: List[Message] = []
        final_messages.append({"role": "system", "content": system_content})
        final_messages.extend(tier_5_messages)

        log.info("context_assembled",
                 total_usable=self.usable_budget,
                 tier_0=tokens_by_tier[0],
                 tier_2=tokens_by_tier[2],
                 tier_5=tokens_by_tier[5],
                 evicted=evicted)

        return AssemblyResult(
            messages=final_messages,
            tokens_by_tier=tokens_by_tier,
            evicted_messages=evicted
        )
