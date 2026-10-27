"""Shell assignment readings: the guarded-reassignment resolver and its budget.

The resolver behind :func:`.shell_normalizer._resolve_local_assignments`: one token
list per reading of a command's guarded reassignments, the co-reference grouping
that decides which choices are enumerated together, the reading budget one payload
walk shares, the fail-closed reading a group past that budget reads as, and the
glued-carrier binding table.  The leaf syntax it reads is
:mod:`.shell_assignment_syntax`; the program and verb recognisers are read late
through :mod:`.shell_normalizer`, so a patch on the reader reaches this module too.
Split out of the reader to hold it under the per-file line cap.
"""

from __future__ import annotations

from typing import overload

from .shell_assignment_syntax import (
    _CONDITIONAL_OPERATORS,
    _CONTROL_OPERATOR_SPLIT_RE,
    _FUNCTION_NAME_RE,
    _IFS_USE_RE,
    _SHLEX_WHITESPACE_RE,
    _SUBSHELL_OPERATORS,
    _command_run_starts,
    _compound_body_flags,
    _ends_in_operator,
    _guarded_body,
    _is_argument_assignment,
    _is_command_scoped_assignment,
    _is_command_word,
    _is_guard_token,
    _leading_assignments,
    _mask_redirections,
    _over_cap_group_is_fail_closed,
    _quote_state_after,
    _split_glued_operators,
    _token_in_command_position,
    _trailing_operator,
)
from .shell_normalizer_programs import _NESTED_SHELL_PROGRAMS, _NESTED_SHELL_VERBS
from .shell_normalizer_redirects import _CARRIER_SPLIT_WINDOW
from .shell_normalizer_walk import (
    _CONTROL_OPERATOR_RE,
    _LOCAL_ASSIGN_RE,
    _PARAM_DEFAULT_RE,
    _SHELL_ASSIGN_RE,
    _VAR_USE_RE,
    _is_computed_value,
)


def _novel_segments(base: "list[str]", reading: "list[str]") -> "list[str]":
    """*reading* without the simple commands it shares with *base*.

    A further reading of a guarded reassignment differs from the first only in the
    segments that expand a name the choice reached; every other segment is the same
    argv, already read once, and carrying it again multiplies the walk of whatever it
    holds by the number of readings (a 10 KB value expanded 3400 times, read 64 ways).
    Function and alias definitions are resolved before this runs, so a dropped
    definition has already been substituted at its call sites.
    """
    shared = {tuple(segment) for segment in _simple_commands(base)}
    out: list[str] = []
    # Kept by PIPELINE, operators included: a novel command's pipe into an
    # evaluator (``echo "$v token" | sh``) is what the payload predicates read, and
    # a further reading reduced to the command alone lost it (found in review).
    pipeline: list[str] = []
    segment: list[str] = []
    # NOVEL latches once the reading diverges and is never reset: every later segment
    # is then kept even if byte-identical, because a shared command can depend on an
    # earlier novel one (``export RSYNC_RSH=$v; rsync host:/ .`` -- the rsync is
    # identical but reads the reassigned remote shell), which dropping it hid (review).
    novel = False
    for token in reading + [";"]:
        operator = _CONTROL_OPERATOR_RE.fullmatch(token) is not None
        if not operator:
            segment.append(token)
        if not (operator or _ends_in_operator(token)):
            continue
        if segment:
            novel = novel or tuple(segment) not in shared
            pipeline += segment
            segment = []
        # A glued pipe is the token's trailing operator run read as an operator
        # (``"$v token"|& sh``): ``endswith("|")`` missed ``|&``, the pipeline was
        # flushed and ``sh`` dropped with it (found in review).  Any ``|`` keeps the
        # pipeline, ``||`` included: :func:`_pipes_into_evaluator` reads every ``|``
        # as a pipe, and a reading cut at ``||`` hid ``|| sh`` from it.
        if "|" in (token if operator else _trailing_operator(token)):
            if operator:
                pipeline.append(token)
            continue
        if pipeline and novel:
            out += [";"] + pipeline if out else pipeline
        pipeline = []
    return out


def _simple_commands(tokens: "list[str]") -> "list[list[str]]":
    """*tokens* split at the control-operator tokens, operators dropped.

    A token ENDING in an operator (``$b;`` -- ``shlex`` splits on whitespace only)
    ends its segment too, kept whole inside it: the split is only where a shared
    segment is looked up, so a quoted operator mis-read here costs one segment its
    match, never a token its spelling.  An empty token (``""``, an empty argument
    ``shlex`` keeps) ends nothing: indexing its last character raised, the raise
    was swallowed by the frame walk's catch-all, and every self-protection frame
    of a command with a guarded choice and a ``""`` argument was dropped (found
    in review).
    """
    segments: list[list[str]] = []
    segment: list[str] = []
    for token in tokens:
        if _CONTROL_OPERATOR_RE.fullmatch(token):
            if segment:
                segments.append(segment)
            segment = []
            continue
        segment.append(token)
        if _ends_in_operator(token):
            segments.append(segment)
            segment = []
    if segment:
        segments.append(segment)
    return segments


class _ReadingBudget:
    """The rescans and text one WALK may spend on guarded readings, in all.

    Spent per COMMAND, the budget was spent afresh by every frame of the payload
    walk: a ``bash -c`` carrier nested four deep with six guards per level and an
    innermost script that expands every ancestor name yields one distinct payload
    per reading at each level, so ~64 ** 4 frames each paid their own 64 rescans
    and the synchronous gate outlived the loop-stall watchdog (found in review).
    One budget per walk, handed down through every frame, bounds the whole tree.
    """

    __slots__ = ("spent", "spent_volume")

    def __init__(self) -> None:
        self.spent = 0
        self.spent_volume = 0


def _resolve_local_assignment_readings(
    tokens: "list[str]", budget: "_ReadingBudget | None" = None
) -> "list[list[str]]":
    """Substitute ``$VAR`` uses with a literal assigned earlier in the same command.

    Only LITERAL right-hand sides are tracked, and only assignments that appear in
    this same command text -- there is no attempt to model the ambient environment.
    That is enough for the evasion it closes, where the attacker must supply both
    halves themselves.

    A value that REFERENCES an already-tracked variable is expanded before it is
    classified, so a name assembled across several assignments still resolves to the
    literal the shell will run.

    A guarded reassignment of any tracked binding (``x=<cli> && x=bash; $x -c ...``,
    ``v=<verb>; false && v=doctor; <cli> $v``) is read both ways: the guard may skip
    the new value, so the prior still runs, and
    the new value may be a shell whose payload the walk must still descend.  One
    resolved frame carries one program per use, so each further reading is a further
    token list (the first is the command as written).  Each guarded reassignment is
    its own choice: two of them
    read only all-prior and all-new missed ``x=<cli>; false && x=echo; v=doctor;
    true && v=<verb>; $x $v``, which runs the mint (found in review).  Choices
    under two guards SPELLED alike are not one choice either: the text is
    case-folded before it is read, so ``$Path`` and ``$PATH`` are one name here
    and two in bash, and a command between the two tests can rewrite what they
    read; tying them folded away the mixed reading that pairs the prior program
    with the new verb (found in review).  A choice on a
    name that is never expanded again changes no reading and is not enumerated.
    The rest are enumerated as the FULL product within each group of names that
    are expanded in one simple command (:func:`_co_referenced_names`) -- a
    frame's argv is one segment, so choices on names that never meet in a segment
    cannot pair, and enumerating their product bought nothing.  Capping the
    product and folding the choices past the cap onto one shared bit was a
    bypass: three filler guards pushed the program and the verb choices onto the
    shared bit, whose all-prior and all-new readings never pair the prior program
    with the new verb (found in review).  So a group past
    :data:`_GUARDED_READING_CAP` choices is not folded: its reading is the
    fail-closed :data:`_UNREADABLE_GUARDED_READING`, exactly as a regex group
    past its budget reads as ``.*``; so is a group whose readings would expand to
    more than :data:`_GUARDED_READING_VOLUME` of text.  The budget is spent by
    the COMMAND, not by each group: every further reading is one more full
    rescan of the token list, and one group per simple command bounds the
    group count only by the command's length, so 300 one-choice groups under
    the scan ceiling each passed the per-group check and together held the
    loop past its watchdog (found in review).  Past
    ``2 ** _GUARDED_READING_CAP`` readings in all, or past the volume budget
    in all, the command reads as the fail-closed reading and enumeration stops.
    The budget is *budget* when given -- the payload walk's, shared by every frame
    it descends into (:class:`_ReadingBudget`) -- else this command's own.
    """
    resolved, choices = _resolve_local_assignments_once(tokens, frozenset())
    if not choices:
        return [resolved]
    if budget is None:
        budget = _ReadingBudget()
    out = [resolved]
    seen = {tuple(resolved)}
    groups = _co_referenced_names(tokens)
    taken: set[frozenset[_GuardedChoice]] = {frozenset()}
    known: dict[_GuardedChoice, str] = {}
    pending = list(choices)
    volume = sum(len(token) for token in resolved)  # base-reading size = rescan estimate
    while pending:
        # A reading can meet a choice the base reading did not; collect to a fixpoint.
        by_group: dict[frozenset[str], list[_GuardedChoice]] = {}
        for key, name in pending:
            known[key] = name
        pending = []
        for key, name in known.items():
            group = groups.get(name)
            if group is not None:
                by_group.setdefault(group, []).append(key)
        for group, keys in by_group.items():
            # Every choice is its own: guards spelled alike are NOT one test, since
            # the reader case-folds (``$Path``/``$PATH`` read as one, two in bash) and
            # a command between them rewrites what the test reads; tying them folded
            # away the mixed reading that pairs the prior program with the new verb
            # (found in review). Decided before the volume estimate.
            if len(keys) > _GUARDED_READING_CAP:
                # The fold re-walks the token list; charge it to the shared budget so
                # many over-cap groups cannot run up an unbounded aggregate (found in review).
                budget.spent_volume += volume
                if budget.spent_volume > _GUARDED_READING_VOLUME:
                    out.append(list(_UNREADABLE_GUARDED_READING))
                    return out
                if _over_cap_group_is_fail_closed(
                    tokens,
                    # the FULL co-referenced group: a use of an unguarded member
                    # (``y=$x; $y token``) must match the segment filter (review).
                    set(group),
                    _sn._is_protected_program,
                    _sn._is_self_program,
                    _sn._is_ssh_like_program,
                    _sn._is_interpreter_program,
                    _sn._program_basename,
                    _NESTED_SHELL_PROGRAMS,
                    _NESTED_SHELL_VERBS,
                ):
                    out.append(list(_UNREADABLE_GUARDED_READING))
                    return out
                continue
            # A within-cap group past the volume budget is not walked (a DoS).
            if volume << len(keys) > _GUARDED_READING_VOLUME:
                out.append(list(_UNREADABLE_GUARDED_READING))
                return out
            for pick in range(1, 1 << len(keys)):
                take = frozenset(key for i, key in enumerate(keys) if pick >> i & 1)
                if take in taken:
                    continue
                # Spent per rescan, across every group: the aggregate the loop pays.
                if (
                    budget.spent >= (1 << _GUARDED_READING_CAP) - 1
                    or budget.spent_volume + volume > _GUARDED_READING_VOLUME
                ):
                    out.append(list(_UNREADABLE_GUARDED_READING))
                    return out
                budget.spent += 1
                taken.add(take)
                alternate, met = _resolve_local_assignments_once(tokens, take)
                # Charged at the reading's REAL size: the base keeps each short
                # prior while an alternate takes the long guarded value, so a
                # base-sized charge let a 140 MB expansion pass an 8 MB budget
                # (found in review).
                budget.spent_volume += sum(len(token) for token in alternate)
                if budget.spent_volume > _GUARDED_READING_VOLUME:
                    out.append(list(_UNREADABLE_GUARDED_READING))
                    return out
                pending += [choice for choice in met if choice[0] not in known]
                if tuple(alternate) not in seen:
                    seen.add(tuple(alternate))
                    out.append(alternate)
    return out


#: A pipe: the one operator whose two sides are read as one command, in the
#: co-reference grouping and in a further reading's novel segments alike.
_PIPE_OPERATORS = frozenset({"|", "|&"})

#: Words that open a function or alias definition, whose body runs at a call site.
_WRAPPER_WORDS = frozenset({"alias", "function"})

#: Guarded reassignments within one co-referenced group are enumerated exactly up to
#: this many; ``2 ** _GUARDED_READING_CAP`` (64) readings is also the most one
#: COMMAND is rescanned in all, a group past either reading as the fail-closed
#: reading below.
_GUARDED_READING_CAP = 6

#: The most text a command's readings may expand to, in all, each reading charged
#: at its own size: a 10 KB value expanded 3400 times (34 MB, far past the 2 MB the
#: kernel lets a command line carry at all) read 64 ways is never walked.
_GUARDED_READING_VOLUME = 1 << 23

#: The one token of the reading a group the enumeration cannot afford: a NUL byte
#: ends a C string, so no command line can carry this word and no shell text reads
#: as it.  Every floor that consumes a frame (:func:`_is_unreadable_reading`) refuses
#: on it OUTRIGHT instead of reading a fold of the choices that may hide a pairing
#: -- fail closed, as a regex group past its budget reads as ``.*``.  It was the
#: mint spelling, which only the mint floor reads: with that catalog row disabled a
#: ``pkill`` reading past the cap was replaced by a reading the self-kill floor does
#: not match, and the command ran (found in review).
_UNREADABLE_READING_MARK = "\x00unreadable-guarded-reading"
_UNREADABLE_GUARDED_READING = (_UNREADABLE_READING_MARK,)


def _is_unreadable_reading(tokens: "list[str]") -> bool:
    """True when *tokens* carries the fail-closed reading: the consumer must refuse."""
    return _UNREADABLE_READING_MARK in tokens


#: One guarded reassignment: the token that carries it, the segment inside a whole
#: quoted script (``-1`` at top level, ``-2`` for a command-scoped prefix) and the
#: name.  Keyed by POSITION rather than by firing order, so a reading that meets a
#: choice the base reading did not shifts none of the others.
_GuardedChoice = tuple[int, int, str]


def _guarded_choice(take: "frozenset[_GuardedChoice]", key: "_GuardedChoice") -> bool:
    """True when the guarded reassignment *key* keeps the prior under *take*."""
    return key not in take


def _mask_expansion_operators(token: str) -> str:
    """Blank the control operators that sit INSIDE a ``$``-expansion.

    ``${v#;}`` carries a ``;`` that is data, not a command separator.  Replacing
    those chars in place (length preserved, so spans still map to the original)
    before the co-reference split keeps the names around the expansion in one
    simple command's group.
    """
    chars = list(token)
    for regex in (
        _VAR_USE_RE,
        _sn._PARAM_TRANSFORM_RE,
        _sn._INDIRECT_VAR_USE_RE,
        _PARAM_DEFAULT_RE,
    ):
        for match in regex.finditer(token):
            for i in range(match.start(), match.end()):
                if chars[i] in ";&|\n":
                    chars[i] = "_"
    return "".join(chars)


def _co_referenced_names(tokens: "list[str]") -> "dict[str, frozenset[str]]":
    """Each expanded name -> the names it can meet in one simple command's argv.

    Names expanded in the same segment (between control operators) are one group,
    and a pipe joins its two sides: what one side writes the other runs (``echo $v
    | $x``), so a choice on either reaches the pair (found in review).  A name
    whose assignment expands another (``y=$x``) joins that name's group,
    since a choice on ``x`` reaches wherever ``y`` is expanded.  An INDIRECT use
    (``${!n}``) names its target at run time, so a command carrying one is a single
    group.  A name never expanded is absent: no reading depends on it.
    """
    parent: dict[str, str] = {}

    def find(name: str) -> str:
        while parent.setdefault(name, name) != name:
            name = parent[name]
        return name

    def union(names: "list[str]") -> None:
        roots = {find(name) for name in names}
        root = roots.pop()
        for other in roots:
            parent[other] = root

    def uses(text: str) -> "list[str]":
        names = [m.group(1) or m.group(2) for m in _VAR_USE_RE.finditer(text)]
        names += [m.group(1) for m in _sn._PARAM_TRANSFORM_RE.finditer(text)]
        return names + [m.group(1) for m in _sn._INDIRECT_VAR_USE_RE.finditer(text)]

    referenced: set[str] = set()
    indirect = False
    wrapper = False
    segment: list[str] = []
    for token in _split_glued_operators(tokens) + [";"]:
        if _CONTROL_OPERATOR_RE.fullmatch(token):
            if token in _PIPE_OPERATORS:
                continue
            if segment:
                union(segment)
            segment = []
            continue
        # A token with no ``$`` still CLOSES a segment when it is a use glued to its
        # separator (``q;echo``): the ``$`` test is only a fast path around ``uses()``,
        # not a skip of the boundary, or seven independent guards union into one group
        # and an ordinary command reads as unreadable (found in review).
        # A redirection's ``&`` (``2>&1``, ``>&2``, ``&>``) is no separator either: it
        # is masked before the boundary test, or one simple command was read as two
        # and the names on either side of the redirection never paired (review).
        # A function or alias body runs at its call sites, so the names it expands meet
        # the call's arguments in one argv; like an indirect use, a definition makes the
        # command one group (found in review: ``f(){ $x "$@"; }; f $v`` split them).
        wrapper = wrapper or token in _WRAPPER_WORDS or bool(_FUNCTION_NAME_RE.match(token))
        operators = _mask_redirections(token)
        glued_boundary = bool(_CONTROL_OPERATOR_RE.search(operators)) and not (
            _SHLEX_WHITESPACE_RE.search(token)
        )
        if "$" not in token and not glued_boundary:
            continue
        indirect = indirect or bool(_sn._INDIRECT_VAR_USE_RE.search(token))
        names = uses(token)
        # ``NAME+=$p`` appends the tracked value, so the append form co-references
        # too; matching ``=`` alone put ``q`` in its own group and the pairing of
        # ``p``'s prior program with ``v``'s new verb was never read (found in review).
        assign = _LOCAL_ASSIGN_RE.match(token) or _SHELL_ASSIGN_RE.match(token)
        if assign and not _CONTROL_OPERATOR_RE.search(operators):
            union([assign.group(1)] + names)  # a value that expands a tracked name
            # a name used only inside an assignment value (``RSYNC_RSH=$v``) must
            # reach ``live`` AND this command's segment, or the pairing that makes
            # the value a channel and the command word ``rsync`` is never read as
            # one simple command (found in review).
            referenced.update(names)
            segment += names
            continue
        referenced.update(names)
        if not glued_boundary:
            segment += names
            continue
        # A use GLUED to its separator (``echo $a; echo $b``, ``$a;echo $b`` --
        # ``shlex`` splits on whitespace only) ends its simple command there, as in
        # :func:`_simple_commands`; read on, unrelated commands were one group and
        # seven guards with no self reference read as unreadable (found in review).
        # A whole quoted script is one whitespace-bearing token and stays one segment.
        # An operator INSIDE an expansion (``${v#;}``) is no separator: mask the
        # expansion spans before locating separators, so it closes no segment and the
        # co-referenced names stay in one group (found in review: ``$x ${v#;}`` split
        # ``x`` and ``v`` apart and the mint pairing ``kirocrew token`` was never read).
        masked = _mask_redirections(_mask_expansion_operators(token))
        in_pieces: list[str] = []
        last = 0
        for match in _CONTROL_OPERATOR_RE.finditer(masked):
            in_pieces += uses(token[last : match.start()])
            segment += uses(token[last : match.start()])
            if token[match.start() : match.end()] not in _PIPE_OPERATORS:
                if segment:
                    union(segment)
                segment = []
            last = match.end()
        in_pieces += uses(token[last:])
        segment += uses(token[last:])
        segment += [name for name in names if name not in in_pieces]
    if (indirect or wrapper) and (parent or referenced):
        union(list(parent) + list(referenced))
    groups: dict[str, list[str]] = {}
    for name in parent:
        groups.setdefault(find(name), []).append(name)
    live = {find(name) for name in referenced}
    return {
        name: frozenset(members)
        for root, members in groups.items()
        if root in live
        for name in members
    }


class _GluedBindings:
    """The resolver's name -> literal table, reading a GLUED first name under its suffixes.

    A ``-c`` carrier glued to its script (``-C<flags>c'<name>=<cli>; $<name> <verb>'``)
    folds to one letter run in which the option letters and the assignment name are
    indistinguishable (:func:`_shell_c_carrier_payloads`).  A name LONGER than the split
    window is only ever such a run: no rule-covered program is that long, so its
    leading letters are flags and the name is some suffix.  Which one is decided by
    the script's own use of it, so a use of any suffix of the first name -- separated
    from it by letters alone -- reads that name's binding.  A use is a lookup, so the
    cost is one suffix comparison per use: linear, where enumerating one payload per
    referenced suffix was not.  A plain command's first word is shorter than the
    window, so the reading never fires for it.
    """

    __slots__ = ("_values", "_glued")

    def __init__(self) -> None:
        self._values: dict[str, str] = {}
        self._glued = ""

    def glue(self, name: str) -> None:
        """Record the FIRST name of the frame when it is longer than the split window."""
        if len(name) > _CARRIER_SPLIT_WINDOW:
            self._glued = name

    def _key(self, name: str) -> str:
        if name in self._values or not name or not self._glued.endswith(name):
            return name
        letters = self._glued[: -len(name)]
        return self._glued if letters and letters.isascii() and letters.isalpha() else name

    @overload
    def get(self, name: str) -> "str | None": ...

    @overload
    def get(self, name: str, default: str) -> str: ...

    def get(self, name: str, default: "str | None" = None) -> "str | None":
        return self._values.get(self._key(name), default)

    def prior(self, name: str) -> "str | None":
        """The binding recorded under *name* ITSELF, for an ASSIGNMENT to *name*.

        The suffix reading serves a use (``$<name>``); an assignment names its own
        variable.  Read through the fold, ``v=<verb>`` after a 65-letter first
        assignment ending in ``v`` was "already bound", the prefix-scoped branch
        recorded nothing, and ``$v`` then read the filler's value (found in review).
        """
        return self._values.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._values

    def __setitem__(self, name: str, value: str) -> None:
        self._values[name] = value

    def set_folded(self, name: str, value: str) -> None:
        """Record *value* under the glued key *name* folds to (a plain name folds to
        itself), so an append to a suffix extends the glued binding, not a bare one."""
        self._values[self._key(name)] = value

    def __bool__(self) -> bool:
        return bool(self._values)


def _resolve_local_assignments_once(
    tokens: "list[str]", take: "frozenset[_GuardedChoice]"
) -> "tuple[list[str], list[tuple[_GuardedChoice, str]]]":
    """One reading of :func:`_resolve_local_assignments`.

    Each guarded or subshell-scoped reassignment met is a choice keyed by its
    position; *take* names the ones read as taken (:func:`_guarded_choice`).  The
    second result lists the choices this reading met, each with its name.
    """
    values = _GluedBindings()
    out: list[str] = []
    met: list[tuple[_GuardedChoice, str]] = []
    # ``X=<name>;$X <verb>`` glues the assignment and next command into ONE token
    # (``shlex`` splits on whitespace); split on control operators first.
    tokens = _split_glued_operators(tokens)
    # End of each token's assignment run, computed once (a per-token walk was quadratic).
    # ``_SHELL_ASSIGN_RE`` matches an APPEND (``A+=b``) so the run does not end at one --
    # ending it there read ``v=doctor; v=token A+=b`` as a prefix and left the mint
    # binding unreplaced (found in review); it is the predicate the position checks use.
    run_end = _sn._next_stop_indexes(tokens, lambda tk: _SHELL_ASSIGN_RE.match(tk) is None)
    cmd_start = _command_run_starts(tokens)  # run-start table: kills the O(n^2) re-walk
    # Inside a compound body every statement is guarded, not only the first (found in
    # review: ``if false; then y=1; x=echo; fi`` hid the reassignment after ``y=1``).
    in_body = _compound_body_flags(
        tokens, lambda at: _token_in_command_position(tokens, at, cmd_start), True
    )
    for idx, token in enumerate(tokens):
        assign = _LOCAL_ASSIGN_RE.match(token)
        subshell_scoped = False
        if idx == 0:
            # Both spellings: a glued carrier opening with an APPEND (``<flags>c'<name>+=<cli>;
            # $<suffix> <verb>'``) took no glued name and the use never resolved (found in review).
            first = _SHELL_ASSIGN_RE.match(token)
            if first:
                values.glue(first.group(1))
        if assign:
            # ``X=foo true`` is a prefix scoped to ONE command: it must not REPLACE the
            # shell's binding (``x=<cli>; x=foo true; $x <verb>`` mints), but a FIRST
            # binding is recorded (the command inherits it), as is a protected value.
            # A value opening a substitution or quote spans the following tokens.
            value_text = assign.group(2)
            spans_tokens = (
                "$(" in value_text
                or "`" in value_text
                or value_text.count('"') % 2 == 1
                or value_text.count("'") % 2 == 1
            )
            look = run_end[idx]
            prefix_value = _VAR_USE_RE.sub(
                lambda m: values.get(m.group(1) or m.group(2), m.group(0)), value_text
            )
            scoped = (
                not spans_tokens
                and look < len(tokens)
                and assign.group(1) in values
                and not _sn._is_protected_program(prefix_value.strip("\"'"))
            )
            if scoped and tokens[look].startswith("#"):
                # ``shlex`` dropped the quotes, so a comment (``#x``, the rest of the
                # line gone) and a quoted command (``'#x'``, the prefix scoped to it)
                # arrive alike: one more choice, read both ways (found in review).
                key = (idx, -2, assign.group(1))
                scoped = _guarded_choice(take, key)
                met.append((key, assign.group(1)))
            elif scoped:
                scoped = _is_command_word(tokens[look])
            if scoped:
                out.append(token)
                continue
            subshell_scoped = look < len(tokens) and tokens[look] in _SUBSHELL_OPERATORS
        # ``NAME+=tail`` APPENDS, and the pattern above cannot match it at all (``+`` is
        # not a name character), so an appended PROGRAM word was invisible here: `F=fi;
        # F+=nd; $F <fenced> -exec cat {} +` ran a `find` this resolver never saw, while
        # its single-assignment twin `F=fin; ${F}d` -- closed in an earlier round --
        # denied (found in review). Seven spellings did it, including an empty initial
        # value, repeated appends, a quoted tail and an append feeding a braced use.
        #
        # Append is in the same closed class as those: the tail is a LITERAL, so what the
        # shell will run is decided by the text alone. That is what separates it from
        # `$(printf find)`, whose value needs a program run and is out of scope here.
        #
        # `_SHELL_ASSIGN_RE` is REUSED rather than a second append pattern being added:
        # it already carries the optional ``+`` group for this exact problem on the
        # path-tracking side, so there is one spelling of the rule in the module. It is
        # matched only in the branch the assignment pattern rejects, which keeps this
        # additive -- renumbering the shared pattern's groups instead would have rewritten
        # every existing reader of them for no behavioural gain.
        append = None if assign else _SHELL_ASSIGN_RE.match(token)
        # An append that OPENS a whole quoted script is that script's first command,
        # not one append with the rest of the script as its tail: it is read below
        # with the script (found in review: the tail reading was an accident).
        if (
            append
            and append.group(2)
            and not (_SHLEX_WHITESPACE_RE.search(token) and _CONTROL_OPERATOR_RE.search(token))
        ):
            name, tail = append.group(1), append.group(3)
            if values and "$" in tail:
                # Same reason the assignment path expands first: a tail built from an
                # already-tracked variable is a literal once expanded, and left
                # unexpanded it reads as computed and the append is dropped.
                tail = _VAR_USE_RE.sub(
                    lambda m: values.get(m.group(1) or m.group(2), m.group(0)), tail
                )
            if _is_computed_value(tail):
                # No literal to concatenate. Over-approximate exactly as the assignment
                # path does: the value only matters where it is later used as a program,
                # so a wrong guess there is a refusal rather than a bypass.
                produced = _sn._protected_name_in_substitution(tokens, idx)
                if produced:
                    values[name] = produced
                out.append(token)
                continue
            piece = tail.strip("\"'").rstrip(";&|")
            # A guarded or subshell-scoped APPEND may not run either, so it is one more
            # choice read both ways: ``q=<cli>; false && q+=zzz; $q <verb>`` ran the
            # mint while the ``=`` spelling was already refused (found in review).
            prior = values.get(name)
            if (
                piece
                and prior is not None
                and (
                    in_body[idx]
                    or (idx > 0 and _is_guard_token(tokens[idx - 1]))
                    or (run_end[idx] < len(tokens) and tokens[run_end[idx]] in _SUBSHELL_OPERATORS)
                    or _is_argument_assignment(tokens, idx, cmd_start)
                )
            ):
                key = (idx, -3, name)
                met.append((key, name))
                if _guarded_choice(take, key):
                    out.append(token)
                    continue
            # `F=` records nothing, so an append to an unset name starts from empty
            # rather than being discarded -- that was one of the seven spellings, and
            # bash builds the value the same way.
            values.set_folded(name, (prior or "") + piece)
            out.append(token)
            continue
        if (
            values
            and "$" in token
            and _CONTROL_OPERATOR_RE.search(token)
            and (assign or _SHLEX_WHITESPACE_RE.search(token))
        ):
            # A whole quoted SCRIPT (see :func:`_split_glued_operators`): this frame's
            # binding is expanded into it only UNTIL the script assigns the name itself,
            # segment by segment; a guarded or subshell-scoped assignment does not.
            inner: set[str] = set()
            appended: dict[str, str] = {}
            quote = ""
            # Quotes are syntax only in a quoted whole script; in a token ``shlex``
            # split bare they are escaped literals (see :func:`_split_glued_operators`).
            script = bool(_SHLEX_WHITESPACE_RE.search(token))
            parts = _CONTROL_OPERATOR_SPLIT_RE.split(token)
            # The body flag is sticky over a compound command here too (found in
            # review); every segment is a command, so none is quoted data.
            body_flags = _compound_body_flags([p.strip() for p in parts], lambda _at: True, False)
            for pos, segment in enumerate(parts):
                # A separator INSIDE a quote is data: the segment after it is the
                # rest of a word, not a command, so it assigns nothing.
                opens_quoted = bool(quote)
                quote = _quote_state_after(segment, quote) if script else ""
                if _CONTROL_OPERATOR_RE.fullmatch(segment):
                    continue

                def outer(name: str, whole: str) -> str:
                    # A use reads through the glued first name's suffix fold
                    # (:class:`_GluedBindings`); membership alone did not (found in review).
                    value = values.get(name)
                    if name in inner or value is None:
                        return whole
                    return value + appended.get(name, "")

                segment = _sn._PARAM_TRANSFORM_RE.sub(
                    lambda m: outer(m.group(1), m.group(0)), segment
                )
                segment = _sn._INDIRECT_VAR_USE_RE.sub(
                    lambda m: outer(values.get(m.group(1), ""), m.group(0)), segment
                )
                segment = _VAR_USE_RE.sub(
                    lambda m: outer(m.group(1) or m.group(2), m.group(0)), segment
                )
                parts[pos] = segment
                # A name is the script's own when ITS value is protected or the run
                # persists; a protected sibling (``x=echo y=<cli> true``) is not enough.
                # A PROTECTED outer binding is never shadowed: ``shlex`` dropped the
                # quote kind, and in double quotes the outer shell expands the use
                # before the script's own assignment runs (``eval "x=echo; $x token"``
                # mints), so the outer value is the reading that refuses.
                guard_word, body = _guarded_body(segment.lstrip())
                guarded = (
                    guard_word
                    or body_flags[pos]
                    or (pos > 0 and parts[pos - 1].strip() in _CONDITIONAL_OPERATORS)
                )
                subshell = pos + 1 < len(parts) and parts[pos + 1].strip() in _SUBSHELL_OPERATORS
                persists = not guarded and not subshell and not _is_command_scoped_assignment(body)
                for name, value, appends in _leading_assignments(body):
                    # An append EXTENDS the outer value and never replaces it: the
                    # outer binding stays live (``x=<cli>; eval 'x+=" -v"; $x <verb>'``
                    # still runs ``<cli>``), so it takes no inner name -- and its tail
                    # is read onto the outer value (``x=kiro; eval 'x+=crew; $x
                    # <verb>'`` mints), both ways when guarded (found in review).
                    if appends:
                        if opens_quoted or name in inner or name not in values:
                            continue
                        if guarded or subshell:
                            key = (idx, pos, name)
                            met.append((key, name))
                            if _guarded_choice(take, key):
                                continue
                        appended[name] = appended.get(name, "") + value
                        continue
                    # ... and a VERB binding is as live as a program one (as at top
                    # level): ``v=<verb>; eval "v=doctor; <cli> $v"`` mints.
                    if opens_quoted or _sn._is_protected_program(values.get(name, "")):
                        continue
                    if _sn._is_mint_verb(values.get(name, "")):
                        continue
                    if persists or _sn._is_protected_program(value):
                        inner.add(name)
                    elif (guarded or subshell) and name in values:
                        # The guard may or may not run: both the outer and the
                        # script's own value are read (further readings), as at top level.
                        key = (idx, pos, name)
                        met.append((key, name))
                        if not _guarded_choice(take, key):
                            inner.add(name)
            out.append("".join(parts))
            continue
        if assign and values and "$" in (assign.group(2) or ""):
            # A new value may be built FROM a variable already tracked
            # (``x=p; x=${x}kill``).  Expanding before classifying is what makes the
            # result a literal at all: left unexpanded it looks computed, the earlier
            # binding stays in place, and the reassignment is silently ignored.
            expanded = _VAR_USE_RE.sub(
                lambda m: values.get(m.group(1) or m.group(2), m.group(0)),
                assign.group(2),
            )
            if expanded != assign.group(2):
                token = f"{assign.group(1)}={expanded}"
                assign = _LOCAL_ASSIGN_RE.match(token)
        if assign and _is_computed_value(assign.group(2)):
            # ``X=$(printf <name>); $X <verb>`` COMPUTES the value, so there is no
            # literal to carry forward.  Resolve it conservatively instead: if the
            # substitution that produces it names a protected program anywhere, treat
            # the variable as holding that name.  Over-approximating here is the safe
            # direction -- the value only matters when ``$X`` is later used as a
            # program, and a wrong guess there is a refusal, not a bypass.
            produced = _sn._protected_name_in_substitution(tokens, idx)
            if produced:
                values[assign.group(1)] = produced
            elif _sn._mint_verb_in_substitution(tokens, idx):
                # ``T=$(printf <verb>); <name> $T`` computes the VERB rather than the
                # program.  Same reasoning as the program case: the value only matters
                # where it is later used, so binding it to the verb is the safe
                # over-approximation.
                values[assign.group(1)] = "token"
            out.append(token)
            continue
        if assign and assign.group(2):
            # A trailing ``;``/``&&`` belongs to the command structure, not the
            # value: ``shlex`` splits on whitespace only, so ``X=name;`` arrives with it.
            value = assign.group(2).strip("\"'").rstrip(";&|")
            # A guarded or subshell-scoped reassignment (``X=<cli> || X=echo``,
            # ``v=<verb>; false && v=doctor``) may not run, so it does not hide ANY
            # prior value, and the new value is read too (a further reading): only the
            # ``bash`` reading of ``x=<cli> && x=bash`` descends into ``$x -c ...``. So
            # is an assignment-shaped ARGUMENT: the command it follows may run it
            # (``eval``) or print it, so ``echo 'x=echo; ...'`` must not overwrite
            # ``x=<cli>`` (found in review).
            prior = values.prior(assign.group(1))
            if prior is None:
                # A glued long-name carrier binds the first name under its glued key,
                # so a bare-name assignment's own prior is unbound; read it through the
                # fold so a guarded suffix reassignment is enumerated (found in review).
                prior = values.get(assign.group(1))
            if (
                value
                and prior is not None
                and value != prior
                and (
                    in_body[idx]
                    or (idx > 0 and _is_guard_token(tokens[idx - 1]))
                    or subshell_scoped
                    or _is_argument_assignment(tokens, idx, cmd_start)
                )
            ):
                key = (idx, -1, assign.group(1))
                met.append((key, assign.group(1)))
                if _guarded_choice(take, key):
                    value = prior
            if value:
                # A plain ``=`` binds its OWN name, not set_folded (folding a short
                # name onto a glued key overwrites the mint -- a bypass; review).
                values[assign.group(1)] = value
            out.append(token)
            continue
        if values and "$" in token:
            # ``${!V}`` is INDIRECT: it expands to the value of the variable NAMED by
            # ``V``, so resolving it takes two hops through the same table.  Done before
            # the ordinary substitution so what remains afterwards is a plain literal.
            # A TRANSFORMATION on a tracked variable (``${K:0}``, ``${K^^}``, ``${K/x/y}``)
            # is not a plain ``${K}``; it is resolved to the value itself (over-approximating,
            # the safe direction: a wrong guess where it is used as a program is a refusal,
            # not a bypass).  The ``:-``/``:+``/``:=``/``:?`` DEFAULT forms are excluded:
            # they carry their own literal and are resolved separately.
            token = _sn._PARAM_TRANSFORM_RE.sub(lambda m: values.get(m.group(1), m.group(0)), token)
            token = _sn._INDIRECT_VAR_USE_RE.sub(
                lambda m: values.get(values.get(m.group(1), ""), m.group(0)), token
            )
            token = _VAR_USE_RE.sub(
                lambda m: values.get(m.group(1) or m.group(2), m.group(0)), token
            )
            # A use in COMMAND position of a value holding whitespace is word-split
            # (``x="<cli> -v"; $x <verb>`` runs ``<cli>``); an argument stays one word.
            # Command position is the first word after a boundary and that command's
            # leading assignments -- not what follows an assignment-shaped ARGUMENT
            # (``make CFLAGS=-O2 $x``).  ``shlex`` glues a trailing separator to its
            # word (``true;``) and drops the quotes, so a quoted operand ending in one
            # (``grep 'a;' $x``) reads as a boundary too: a refusal, not a bypass.
            # ``$IFS`` in such a use is a separator too (``$x${IFS}<verb>``; found in
            # review) -- quoted or not, since ``shlex`` dropped the quotes: a refusal.
            if token != tokens[idx] and _token_in_command_position(tokens, idx):
                token = _IFS_USE_RE.sub(" ", token)
            if (
                token != tokens[idx]
                and _SHLEX_WHITESPACE_RE.search(token)
                and not _SHLEX_WHITESPACE_RE.search(tokens[idx])
                and _token_in_command_position(tokens, idx)
            ):
                out.extend(token.split())
                continue
        out.append(token)
    return out, met


# Read late, as an attribute, at call time: the reader imports this module while it
# is itself still initializing, so the binding is made last.
from . import shell_normalizer as _sn  # noqa: E402
