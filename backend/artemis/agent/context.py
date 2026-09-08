from typing import Any, Dict, List, Tuple
from dataclasses import dataclass, field
import sqlite3

from ..models.base import Message
from ..obs.logging import get_logger

log = get_logger("agent.context")

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
    def __init__(self, num_ctx: int, reserved_output_reasoning_headroom: int = 2048):
        self.num_ctx = num_ctx
        # The reserve must account for model-generated answer tokens AND reasoning tokens.
        self.reserved_output_reasoning_headroom = reserved_output_reasoning_headroom
        self.safety_margin = 256
        # Invariant: assembled prompt tokens + reserved output/reasoning headroom + safety margin <= num_ctx
        self.usable_budget = max(0, self.num_ctx - self.reserved_output_reasoning_headroom - self.safety_margin)

        self.tier_0_cap = 500
        self.tier_1_cap = 900   # tool schemas (docs/agent.md §4)
        self.tier_2_cap = 300
        self.tier_6_cap = 1200  # current task state + recent tool results

    def assemble(
        self,
        raw_messages: List[sqlite3.Row],
        tool_catalog: str = "",
        tool_results: List[Dict[str, str]] | None = None,
        standing_instruction: str = "",
    ) -> AssemblyResult:
        """
        Assemble messages enforcing budgets.
        Tier 0: System instructions
        Tier 1: Tool schemas (compact, trimmed to the cap)
        Tier 2: User profile/preferences
        Tier 5: Verbatim turns (newest first, oldest evicted)
        Tier 6: Recent tool results (oldest evicted first)

        Eviction order when over budget is 6 → 3 → 4 → 5 → 1; tiers 0 and 2 are
        inviolable (``docs/agent.md`` §4).
        """
        tokens_by_tier = {0: 0, 1: 0, 2: 0, 5: 0, 6: 0}

        # 1. Tier 0 - System instructions.
        system_content = "You are ARTEMIS, a helpful local AI assistant."
        if standing_instruction:
            system_content = f"{system_content}\n{standing_instruction}"
        tier_0_tokens = estimate_tokens(system_content)
        tokens_by_tier[0] = tier_0_tokens

        # 2. Tier 1 - Tool schemas, trimmed to the cap rather than dropped whole.
        tool_block = ""
        if tool_catalog:
            lines = tool_catalog.splitlines()
            kept: List[str] = []
            used = 0
            header = "Available tools (call one by replying with a single JSON object " \
                     '{"tool": "<name>", "arguments": {...}}):'
            used += estimate_tokens(header)
            for line in lines:
                cost = estimate_tokens(line)
                if used + cost > self.tier_1_cap:
                    break
                kept.append(line)
                used += cost
            if kept:
                tool_block = header + "\n" + "\n".join(kept)
                tokens_by_tier[1] = estimate_tokens(tool_block)

        # 3. Tier 2 - Profile (Phase 6 owns the content; the slot exists now).
        tokens_by_tier[2] = 0

        # 4. Tier 6 - Recent tool results, newest kept first.
        tier_6_messages: List[Message] = []
        if tool_results:
            used = 0
            for entry in reversed(tool_results):
                cost = estimate_tokens(entry["content"])
                if used + cost > self.tier_6_cap:
                    break
                tier_6_messages.insert(0, {
                    "role": "tool" if entry.get("role") == "tool" else "system",
                    "content": entry["content"],
                })
                used += cost
            tokens_by_tier[6] = used

        # 5. Tier 5 - Verbatim turns.
        tier_5_budget = max(
            0,
            self.usable_budget
            - tokens_by_tier[0]
            - tokens_by_tier[1]
            - tokens_by_tier[2]
            - tokens_by_tier[6],
        )

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
        if tool_block:
            final_messages.append({"role": "system", "content": tool_block})
        final_messages.extend(tier_5_messages)
        final_messages.extend(tier_6_messages)

        log.info("context_assembled",
                 total_usable=self.usable_budget,
                 tier_0=tokens_by_tier[0],
                 tier_1=tokens_by_tier[1],
                 tier_2=tokens_by_tier[2],
                 tier_5=tokens_by_tier[5],
                 tier_6=tokens_by_tier[6],
                 evicted=evicted)

        return AssemblyResult(
            messages=final_messages,
            tokens_by_tier=tokens_by_tier,
            evicted_messages=evicted
        )
