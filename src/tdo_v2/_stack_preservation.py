"""Independent raw-leaf byte identity for the stack-switch check.

This is a consumer of the existing normalizer and summary copy tracer, not
an ABI or a second reaching-definition analysis. A missing/conditional proof
is NOT preservation. The caller may still use its explicitly named legacy
check exception; an unconditional but nonidentity result overrides that
exception with UNKNOWN (not a claim that the byte necessarily changed).
One instance, including failures, belongs to one program check only.
"""

from ._scope_contracts import VarnodeKindCode
from .function_summary import SummaryKind, summarize_function
from .model import ResolvedStorage, StorageRef, VarnodeKind
from .normalize import FunctionNormalizer, NormalizedFunction
from .resource_limits import AnalysisBudgetExceeded, activation, charge, checkpoint, step
from .storage import _resolve_validated_storage


def _leaf_summary(unit):
    from .may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES
    from .relative_memory import IMAGE_BASE_TRACKING, IMPORT_SLOTS

    observation = unit.observation
    if observation is None:
        return None
    # No outer model/readonly/frame/import/trap policy can license this proof.
    settings = ((ENTRY_VALUES_NOT_FRAME, False), (OPAQUE_NO_STACK_ADDRESSES, False),
                (IMPORT_SLOTS, None), (IMAGE_BASE_TRACKING, None))
    tokens = [(variable, variable.set(value)) for variable, value in settings]
    try:
        with activation(("function", unit.scopes.function.scope)):
            for row in observation.instructions:
                for op in row.operations:
                    step()
                    if op.opcode in ("CALL", "CALLIND", "CALLOTHER", "BRANCHIND"):
                        return None
            normalized = FunctionNormalizer().normalize(unit, assume_globals_disjoint_from_stack=False)
            if type(normalized) is not NormalizedFunction:
                return None
            summary = summarize_function(normalized, observation)
            checkpoint()
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)
    if not summary.exits or summary.tail_exits or summary.dead_exits or summary.inner_calls:
        return None
    return summary


class LeafPreservation:
    def __init__(self, functions):
        self.functions = functions
        self.summaries = {}
        self.decisions = {}

    def decision(self, callee, space, start, size):
        """'identity', 'unknown', or None (no independent decision).

        The unit is obtained only from the current admitted program map;
        callers cannot submit a certificate, another occurrence's summary,
        or a span from another register space.
        """
        key = callee, space, start, size
        if key in self.decisions:
            return self.decisions[key]
        unit = self.functions[callee]
        if callee not in self.summaries:
            try:
                self.summaries[callee] = _leaf_summary(unit)
            except (AnalysisBudgetExceeded, RecursionError) as error:
                if isinstance(error, AnalysisBudgetExceeded) and error.scope == "run":
                    raise
                self.summaries[callee] = None
        summary = self.summaries[callee]
        result = None
        if summary is not None:
            place = _resolve_validated_storage(
                StorageRef(VarnodeKind.REGISTER, "", start, size, space_id=space),
                unit.scopes.resolution_context,
            )
            if type(place) is ResolvedStorage:
                with activation(("function", unit.scopes.function.scope)):
                    result = self._span(unit, summary, place.span)
                    checkpoint()
        self.decisions[key] = result
        return result

    @staticmethod
    def _span(unit, summary, span):
        # A conditional or debt-bearing leaf must never become a negative
        # claim about preservation either: keep the explicit legacy policy.
        if summary.writer_conditions:
            return None
        identity = True
        for exit in summary.exits:
            step()
            covered = set()
            for run in exit.runs:
                step()
                if run.span.object_id != span.object_id:
                    continue
                low, high = max(span.start, run.span.start), min(span.end, run.span.end)
                if low >= high:
                    continue
                if run.debts or run.conditions or run.crossed or run.kind is SummaryKind.UNKNOWN:
                    return None
                charge(high - low)
                covered.update(range(low, high))
                identity &= run.kind is SummaryKind.IDENTITY
            # Untouched bytes are identity only if the admitted raw leaf
            # really has no register output there (not missing terminal SSA).
            for row in unit.observation.instructions:
                for op in row.operations:
                    step()
                    out = op.output
                    if out is None or out.kind is not VarnodeKindCode.REGISTER:
                        continue
                    at = out.coordinate
                    if at.space_id != span.object_id.space_key:
                        continue
                    low, high = max(span.start, at.byte_offset), min(span.end, at.byte_offset + out.byte_size)
                    if any(byte not in covered for byte in range(low, high)):
                        return None
        return "identity" if identity else "unknown"
