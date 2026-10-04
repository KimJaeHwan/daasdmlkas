"""Control-order behavior for one configured function view."""

from __future__ import annotations

from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan
from .configured_interprocedural_records import WriteEvent as _WriteEvent

class _FunctionControlOrderMixin:
    def definitely_precedes(self, left_key: str, right_key: str) -> bool:
        left_position = self.position(left_key)
        right_position = self.position(right_key)
        left_block = self.operation_blocks.get(left_key)
        right_block = self.operation_blocks.get(right_key)
        if (
            left_position is None
            or right_position is None
            or left_block is None
            or right_block is None
        ):
            return False
        if left_block == right_block:
            return left_position < right_position
        return left_block in self._dominators.get(right_block, ())

    def may_precede(self, left_key: str, right_key: str) -> bool:
        """Return whether one observed CFG path orders left before right."""
        return self.can_reach_without_operations(left_key, right_key, ())

    def can_reach_without_operations(
        self,
        left_key: str,
        right_key: str,
        blocked_keys,
    ) -> bool:
        """Return whether a CFG path reaches right after left without blockers."""
        left_position = self.position(left_key)
        right_position = self.position(right_key)
        left_block = self.operation_blocks.get(left_key)
        right_block = self.operation_blocks.get(right_key)
        if (
            left_position is None
            or right_position is None
            or left_block is None
            or right_block is None
        ):
            return False

        blocked_by_block: dict[str, set[int]] = {}
        for operation_key in blocked_keys:
            position = self.position(operation_key)
            block = self.operation_blocks.get(operation_key)
            if position is not None and block is not None:
                blocked_by_block.setdefault(block, set()).add(position)

        if left_block == right_block:
            return left_position < right_position and not any(
                left_position < position < right_position
                for position in blocked_by_block.get(left_block, ())
            )
        if any(
            position > left_position
            for position in blocked_by_block.get(left_block, ())
        ):
            return False
        if any(
            position < right_position
            for position in blocked_by_block.get(right_block, ())
        ):
            return False

        pending = list(self._successors.get(left_block, ()))
        reached = set()
        while pending:
            block = pending.pop()
            if block in reached:
                continue
            reached.add(block)
            if block == right_block:
                return True
            if blocked_by_block.get(block):
                continue
            pending.extend(self._successors.get(block, ()) - reached)
        return False

    def event_reaches_every_exit(
        self, event: _WriteEvent, events: tuple[_WriteEvent, ...]
    ) -> bool:
        """Prove that an observed nested-call write remains live at every exit."""
        call_block = self.operation_blocks.get(event.call_operation_key)
        states = self.memory.observed_terminal_states
        if call_block is None or not states:
            return False
        if any(
            call_block not in self._dominators.get(state.block_key, ())
            for state in states
        ):
            return False
        for definition in self.memory.definitions:
            if (
                definition.kind is MemoryDefinitionKind.DATA_WRITE
                and definition.operation_key is not None
                and any(
                    event.target_span.overlaps(span)
                    for span in self.definition_access_spans(definition)
                )
                and self.definitely_precedes(
                    event.call_operation_key, definition.operation_key
                )
            ):
                return False
        return not any(
            other is not event
            and event.target_span.overlaps(other.target_span)
            and self.definitely_precedes(
                event.call_operation_key, other.call_operation_key
            )
            for other in events
        )

    def event_reaches_an_exit(
        self, event: _WriteEvent, events: tuple[_WriteEvent, ...]
    ) -> bool:
        """Prove one CFG path keeps an observed call write live to an exit."""
        call_block = self.operation_blocks.get(event.call_operation_key)
        terminal_blocks = {
            state.block_key for state in self.memory.observed_terminal_states
        }
        if call_block is None or not terminal_blocks:
            return False
        writes_by_block: dict[str, list[tuple[int, ByteSpan]]] = {}
        for definition in self.memory.definitions:
            operation_key = definition.operation_key
            if (
                definition.kind is not MemoryDefinitionKind.DATA_WRITE
                or operation_key is None
                or operation_key == event.call_operation_key
                or not any(
                    event.target_span.overlaps(span)
                    for span in self.definition_access_spans(definition)
                )
            ):
                continue
            block = self.operation_blocks.get(operation_key)
            position = self.position(operation_key)
            if block is not None and position is not None:
                writes_by_block.setdefault(block, []).append(
                    (
                        position,
                        self.effective_access_span(
                            operation_key,
                            definition.span,
                            read=False,
                        )
                        or definition.span,
                    )
                )
        for other in events:
            if (
                other is event
                or not event.target_span.overlaps(other.target_span)
            ):
                continue
            block = self.operation_blocks.get(other.call_operation_key)
            if block is not None:
                writes_by_block.setdefault(block, []).append(
                    (other.call_position, other.target_span)
                )

        pending = [call_block]
        reached = set()
        while pending:
            block = pending.pop()
            if block in reached:
                continue
            reached.add(block)
            lower_bound = event.call_position if block == call_block else -1
            if any(
                position > lower_bound
                for position, _ in writes_by_block.get(block, ())
            ):
                continue
            if block in terminal_blocks:
                return True
            pending.extend(self._successors.get(block, ()) - reached)
        return False


__all__ = ["_FunctionControlOrderMixin"]
