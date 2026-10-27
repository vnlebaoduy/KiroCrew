"""Tests for kiro_crew.security: the shell reader's guarded-assignment readings.

A credential mint or self-protection action hidden behind a shell-variable
assignment inside a ``-c`` / ``eval`` carrier payload is refused, glued or spaced,
and a guarded reassignment is read both ways: per co-referenced group within the
reading cap, through the over-cap fold past it, and as the fail-closed reading
past the reading budget.
"""

from __future__ import annotations

import pytest


class TestGuardedAssignmentReadings:
    def test_long_assignment_name_glued_carrier_split_is_found_by_its_reference(self) -> None:
        """A first word longer than the window is a NAME, found by its later use.

        A glued ``-Cc'<name>=<program>; $<name> <verb>'`` folds to
        ``-cc<name>=…``, and the letter region runs through the WHOLE
        assignment name up to the ``=``.  With a name longer than the split
        window the only ``c``-run sat outside the window measured from the
        region's end, so the correct split was never a candidate: the payload
        read as ``c<name>=…``, the assignment went to a different name, the
        use never resolved and the mint went unexamined -- while a short name
        was denied.  A word that long is only ever a name with flags glued to
        its front, so the resolver reads its binding under every suffix the
        script refers back to -- whatever padding precedes the option ``c``
        (``-C<78 flags>c'<78 letters>=…'`` puts it out of reach of any fixed
        window from either end) -- in the ONE first-``c`` frame.  Yielding one
        payload per referenced suffix instead grew the candidate set with the
        square root of the token and the scan as O(n^1.5) (found in review).
        """
        from kiro_crew.security import (
            _CARRIER_SPLIT_WINDOW,
            _is_credential_mint,
            _resolve_local_assignments,
            _shell_c_carrier_payloads,
            is_denied,
        )

        long_name = "a" * (_CARRIER_SPLIT_WINDOW + 14)
        padding = "a" * (_CARRIER_SPLIT_WINDOW + 14)
        for name in ("x", long_name):
            for shell in ("zsh", "bash", "sh"):
                for cmd in (
                    f"{shell} -Cc'{name}=kirocrew; ${name} token'",
                    f"{shell} -cc'{name}=kirocrew; ${name} token'",  # folded, written directly
                    f"{shell} -C{padding}c'{name}=kirocrew; ${name} token'",
                    f"{shell} -C{padding}c'{name}(){{ kirocrew token; }}; {name}'",
                    # APPEND spelling of the first assignment: ``+=`` is one keystroke
                    # from the ``=`` spelling above, but ``+`` is not a name character
                    # so ``_LOCAL_ASSIGN_RE`` cannot match it -- the glued name went
                    # unrecorded and the ``$<name>`` use read nothing, so the mint
                    # reached ``is_denied`` as allowed (GPT F1).  Now the first name is
                    # taken with ``_SHELL_ASSIGN_RE`` before append handling.
                    f"{shell} -Cc'{name}+=kirocrew; ${name} token'",
                    f"{shell} -cc'{name}+=kirocrew; ${name} token'",  # folded
                    f"{shell} -C{padding}c'{name}+=kirocrew; ${name} token'",
                    # Empty initial value then a single append also builds the mint
                    # under the glued first name.
                    f"{shell} -Cc'{name}=; {name}+=kirocrew; ${name} token'",
                ):
                    assert _is_credential_mint(cmd.lower(), raw_text=cmd), cmd
                    assert is_denied(cmd) is not None, cmd
        # The long name is NOT enumerated as a split: the first-``c`` frame carries
        # it glued, and the resolver reads the glued first name under the suffix the
        # script uses -- with and without padding, and for a name with a non-letter
        # tail (``name_1``) referenced through it.
        script = f"{long_name}=kirocrew; ${long_name} token"
        assert _shell_c_carrier_payloads(f"-cc{script}") == [f"c{script}"]
        assert _shell_c_carrier_payloads(f"-c{padding}c{script}") == [f"{padding}c{script}"]
        assert (
            _resolve_local_assignments([f"c{long_name}=kirocrew", ";", f"${long_name}", "token"])[
                -2
            ]
            == "kirocrew"
        )
        assert (
            _resolve_local_assignments(
                [f"{padding}c{long_name}_1=kirocrew", ";", f"${long_name}_1", "token"]
            )[-2]
            == "kirocrew"
        )
        # The append spelling of the glued first assignment records under the same
        # glued name, so the ``$<name>`` use resolves to it (GPT F1 regression).
        assert (
            _resolve_local_assignments([f"c{long_name}+=kirocrew", ";", f"${long_name}", "token"])[
                -2
            ]
            == "kirocrew"
        )
        # Only LETTERS may separate the use from the first name (they are the glued
        # flags); a short first name is never read this way; a name bound in its own
        # right wins over the glued reading.
        assert (
            _resolve_local_assignments([f"c1{long_name}=kirocrew", ";", f"${long_name}"])[-1]
            == f"${long_name}"
        )
        assert _resolve_local_assignments(["cx=kirocrew", ";", "$x", "token"])[-2] == "$x"
        assert (
            _resolve_local_assignments(
                [f"c{long_name}=kirocrew", ";", f"{long_name}=echo", ";", f"${long_name}", "token"]
            )[-2]
            == "echo"
        )
        assert _shell_c_carrier_payloads(f"-{padding}c{padding}'ls'") == [f"{padding}'ls'"]
        # Benign spellings with a long assignment name stay allowed.
        assert is_denied(f"bash -Cc'{long_name}=ls; ${long_name} -la'") is None
        assert is_denied(f"bash -C{padding}c'{long_name}=ls; ${long_name} -la'") is None
        assert is_denied(f"bash -Cc'{long_name}+=ls; ${long_name} -la'") is None
        # A glued first assignment then an APPEND to it builds the mint under the folded
        # name: ``<long>=kiro; <long>+=crew`` resolves to ``kirocrew``, not ``crew``.
        for cmd in (
            f"sh -Cc'{long_name}=kiro; {long_name}+=crew; ${long_name} token'",
            f"bash -Cc'{long_name}=kiro; {long_name}+=crew; ${long_name} token'",
        ):
            assert is_denied(cmd) is not None, cmd
        # A GUARDED reassignment of the glued first name is enumerated both ways: the
        # guard may skip it, so the prior mint binding survives -- read through the
        # fold, not shadowed by a bare store (found in review).
        for cmd in (
            f"zsh -Cc'{long_name}=kirocrew; false && {long_name}=echo; ${long_name} token'",
            f"bash -Cc'{long_name}=kirocrew; false || {long_name}=echo; ${long_name} token'",
        ):
            assert is_denied(cmd) is not None, cmd
        # ...and a benign guarded reassignment (no mint prior) stays allowed.
        assert (
            is_denied(f"bash -Cc'{long_name}=ls; false && {long_name}=cat; ${long_name} -la'")
            is None
        )

    def test_a_plain_reassignment_does_not_fold_onto_a_glued_carrier_key(self) -> None:
        """A plain ``=`` reassignment binds its OWN name, never a glued carrier key.

        A glued long first name (``<window+1 a's>=kirocrew``) binds under its glued
        key. A later PLAIN ``a=echo`` -- a short suffix of that key -- must store under
        ``a``, NOT fold onto the glued key and replace ``kirocrew``: folding it dropped
        the mint reading and allowed a ``kirocrew token`` the base branch denies
        (found in review). ``set_folded`` is for the APPEND path only, where the tail
        extends the same binding. The four reassignment forms are verdict-checked here.
        """
        from kiro_crew.security import _CARRIER_SPLIT_WINDOW, is_denied

        glued = "a" * (_CARRIER_SPLIT_WINDOW + 1)
        # plain ``=``: the exact bypass -- a short suffix reassignment must not fold
        # onto the glued key, so the mint binding survives and is denied.
        assert is_denied(f"{glued}=kirocrew; a=echo; ${glued} token") is not None
        assert is_denied(f"{glued}=kirocrew; a=echo; b=1; ${glued} token") is not None
        # glued plain: the glued first name reassigned by its own full spelling still
        # binds under the glued key.
        assert is_denied(f"{glued}=echo; {glued}=kirocrew; ${glued} token") is not None
        # ``+=`` append: the tail extends the glued binding (set_folded path).
        assert is_denied(f"zsh -Cc'{glued}=kiro; {glued}+=crew; ${glued} token'") is not None
        # glued append after a guard: still builds the mint under the glued name.
        assert is_denied(f"{glued}=kiro; true && {glued}+=crew; ${glued} token") is not None
        # a genuinely distinct short var keeps its own binding -- not over-refused.
        assert is_denied(f"{glued}=ls; a=echo; $a -la") is None

    # The most comprehensive over-cap corpus in the suite (~10s locally); a slow
    # shard runner has crossed the global 120s per-test cap, so give it headroom
    # like the other heavy suites do (found in review).
    @pytest.mark.timeout(300)
    def test_a_spaced_carrier_payload_is_walked_whole(self) -> None:
        """A quoted script is ONE operand; its inner ``;`` is not a top-level operator.

        ``bash -c '<name>=<cli>; $<name> <verb>'`` hands the whole script to
        ``-c`` as one token, but the outer frame's assignment resolver split
        that token at its inner ``;`` -- it begins with an assignment and
        carries an operator -- so the payload walk, which takes the ONE token
        after the carrier, descended only ``<name>=<cli>`` and the script's
        own command line was never examined.  Measured ALLOWED for the spaced
        ``-c``, ``eval``, herestring and ``env -S`` carriers at every name
        length while the shell ran the mint (the glued ``-c'…'`` spelling was
        denied, because a ``-``-led token is never split).  A token holding
        whitespace was quoted -- shlex splits on every unquoted whitespace --
        so it is yielded whole AHEAD of its pieces: the whole reaches the walk,
        which re-tokenizes it as its own command line, and the pieces keep
        resolving a top-level glued run whose quoted VALUE holds the space.
        """
        from kiro_crew.security import (
            _CARRIER_SPLIT_WINDOW,
            _is_credential_mint,
            _split_glued_operators,
            is_denied,
        )

        long_name = "a" * (_CARRIER_SPLIT_WINDOW + 14)
        for name in ("x", long_name):
            script = f"{name}=kirocrew; ${name} token"
            for cmd in (
                *(f"{shell} -Cc '{script}'" for shell in ("zsh", "bash", "sh")),
                *(f"{shell} -c '{script}'" for shell in ("zsh", "bash", "sh")),
                f"bash -x -c '{script}'",
                f"bash -c -- '{script}'",
                f'bash -c "{script}"',
                f"eval '{script}'",
                f"bash <<< '{script}'",
                f"env -S '{script}'",
                f"bash -c '{name}=kirocrew;${name} token'",
                f"bash -c '{name}=kirocrew && ${name} token'",
                # The script's own binding wins over an outer one of the same name.
                f"{name}=foo; bash -c '{script}'",
                # An outer binding the script does NOT assign still reaches it
                # (``eval`` runs in the same shell) -- the whole-token reading
                # must not lose it.
                f"y=kirocrew; eval '{name}=${{y}}; ${name} token'",
                f"y=kirocrew; eval '{name}=$y;${name} token'",
                # ...and stays in force until the script reassigns the name: a
                # reassignment AFTER the use does not hide the outer binding.
                f"{name}=kirocrew; eval 'y=1; ${name} token; {name}=foo'",
                f"{name}=kirocrew; eval '${name} token; {name}=foo'",
                # A reassignment GUARDED by ``||``/``&&`` may not run, so it does
                # not hide the protected binding before it -- inside the script,
                # and at top level.
                f"{name}=kirocrew; eval '{name}=kirocrew || {name}=echo; ${name} token'",
                f"eval '{name}=kirocrew || {name}=echo; ${name} token'",
                f"bash -c '{name}=kirocrew && {name}=echo; ${name} token'",
                f"{name}=kirocrew || {name}=echo; ${name} token",
                f"{name}=echo || {name}=kirocrew; ${name} token",
                # A prefix assignment scoped to ONE command (``X=foo true``) leaves
                # the shell's binding untouched, so it does not hide it either.
                f"{name}=kirocrew; eval '{name}=foo true; ${name} token'",
                f"{name}=kirocrew; bash -c '{name}=foo y=bar true; ${name} token'",
                f"{name}=kirocrew; {name}=foo true; ${name} token",
                # A segment's WHOLE leading run of assignments is the script's
                # own binding, not only its first word.
                f"{name}=foo; bash -c 'y=1 {name}=kirocrew; ${name} token'",
                f"{name}=foo; eval 'y=1 {name}=kirocrew; ${name} token'",
                # A reassignment that runs in a SUBSHELL (``| true``, ``&``) never
                # reaches the shell that runs the use, so it does not hide the
                # protected binding either -- inside the script, and at top level.
                f"{name}=kirocrew; eval '{name}=foo | true; ${name} token'",
                f"{name}=kirocrew; eval '{name}=foo & ${name} token'",
                f"{name}=kirocrew; {name}=foo | true; ${name} token",
                f"{name}=kirocrew; {name}=foo & ${name} token",
                f"{name}=kirocrew; {name}=foo | {name}=bar; ${name} token",
            ):
                assert _is_credential_mint(cmd.lower(), raw_text=cmd), cmd
                assert is_denied(cmd) is not None, cmd
        # The unit: a whitespace-bearing token yields the whole first, then the
        # pieces; the glued evasion this splitter exists for has no whitespace
        # and is split exactly as before.
        assert _split_glued_operators(["x=kirocrew; $x token"]) == [
            "x=kirocrew; $x token",
            "x=kirocrew",
            ";",
            " $x token",
        ]
        assert _split_glued_operators(["x=kirocrew\t$x"]) == ["x=kirocrew\t$x"]
        assert _split_glued_operators(["x=kirocrew;$x", "token"]) == [
            "x=kirocrew",
            ";",
            "$x",
            "token",
        ]
        assert is_denied("x=kirocrew;$x token") is not None
        # The glued first name's suffix reading serves a USE only: an assignment
        # to a short name that is a suffix of an unrelated long first name is
        # its own binding, not "already bound" through the fold (found in review:
        # the prefix-scoped branch then recorded nothing and ``$v`` read the
        # filler's value while bash ran the mint).
        filler = "x" * (_CARRIER_SPLIT_WINDOW + 1)
        for spelled in (
            f"{filler}v=1; v=token bash -c 'kirocrew $v'",
            f"{filler}v=1; v=token; kirocrew $v",
            f"{filler}v=1; false && v=token; kirocrew $v",
            f"{filler}x=1; x=kirocrew; $x token",
            f"{filler}x=1; x=kirocrew true; $x token",
            f"{filler}v=1;v=token;kirocrew $v",
        ):
            assert is_denied(spelled) is not None, spelled
        assert is_denied(f"{filler}v=1; v=doctor; kirocrew $v") is None
        assert is_denied(f"{filler}v=1; echo ${filler}v") is None
        # A top-level glued run whose quoted value carries a space still
        # resolves through the pieces -- and so does one whose unquoted
        # non-breaking space shlex never split on.
        assert is_denied('X="a b";Y=kirocrew;$Y token') is not None
        assert is_denied("X=a\u00a0b;Y=kirocrew;$Y token") is not None
        # A quoted kill target reaches the kill check whole, not as a shredded pair
        # -- the same refusal the unshredded target already meets.
        assert is_denied("pkill -f 'x=pkill; $x -f kirocrew'") is not None
        assert is_denied("pkill -f 'KIROCREW_PORT=6777 npm run dev'") is not None
        assert is_denied("pkill -f 'v=6777; KIROCREW_PORT=$v npm run dev'") is not None
        assert is_denied("pkill -f 'v=6777; PORT=$v npm run dev'") is None
        # A guarded reassignment does not hide a KILL program any more than it
        # hides the cli: by name, and by pid through a substitution.
        assert is_denied("x=pkill || x=echo; $x -f kirocrew") is not None
        assert is_denied("x=pkill && x=echo; $x -f kirocrew") is not None
        assert is_denied("x=killall || x=echo; $x kirocrew") is not None
        assert is_denied("x=kill || x=echo; $x -9 $(pgrep -f kirocrew)") is not None
        # Benign scripts stay allowed.
        assert is_denied(f"bash -c '{long_name}=ls; ${long_name} -la'") is None
        assert is_denied("bash -c 'x=echo; $x hello'") is None
        # A script's own reassignment never shadows a PROTECTED outer binding:
        # shlex dropped the quote kind, and in double quotes the outer shell
        # expands the use before the script runs (found in review).
        assert is_denied("x=kirocrew; eval 'x=echo; $x token'") is not None
        assert is_denied('x=kirocrew; eval "true; x=echo; $x token"') is not None
        assert is_denied("x=kirocrew; eval 'true; x=echo; $x token'") is not None
        assert is_denied("x=kirocrew; bash -c 'true; x=echo; $x token'") is not None
        assert is_denied("x=kirocrew; eval 'x=foo y=bar; $x token'") is not None
        # An UNPROTECTED outer binding is shadowed by the script's own.
        assert is_denied("x=ls; eval 'true; x=echo; $x token'") is None
        assert is_denied("x=echo; eval 'true; x=kirocrew; $x token'") is not None
        assert is_denied("x=kirocrew; eval 'x=echo; $x doctor'") is None
        # A guarded reassignment of an unprotected value still takes effect.
        assert is_denied("x=ls || x=echo; $x hello") is None
        # A guarded or subshell-scoped reassignment of a VERB binding is read both
        # ways too: the guard may skip it, so the mint verb is still live (found in
        # review). Inside a script the same two readings apply.
        assert is_denied("v=token; false && v=doctor; kirocrew $v") is not None
        assert is_denied("v=token; true || v=doctor; kirocrew $v") is not None
        assert is_denied("v=token; v=doctor | true; kirocrew $v") is not None
        assert is_denied("v=token; v=doctor & kirocrew $v") is not None
        assert is_denied('v=token; false && v=doctor; kirocrew "$v"') is not None
        assert is_denied("x=doctor; eval 'false && x=token; kirocrew $x'") is not None
        assert is_denied("x=doctor; bash -c 'false && x=token; kirocrew $x'") is not None
        # Each guarded reassignment is its own choice: two bindings may land on
        # opposite sides, so the prior program with the NEW verb is one reading
        # (found in review).  Choices are enumerated exactly within each group of
        # names that meet in one simple command; a choice on a name never expanded
        # again is not a reading.
        assert (
            is_denied("x=kirocrew; false && x=echo; v=doctor; true && v=token; $x $v") is not None
        )
        assert (
            is_denied("x=echo; false && x=kirocrew; v=token; true && v=doctor; $x $v") is not None
        )
        assert is_denied("x=kirocrew; x=echo | true; v=doctor; v=token | true; $x $v") is not None
        assert (
            is_denied("x=kirocrew; eval 'false && x=echo; v=doctor; true && v=token; $x $v'")
            is not None
        )
        assert (
            is_denied("x=kirocrew; false && x=echo; v=doctor; bash -c 'true && v=token; $x $v'")
            is not None
        )
        assert (
            is_denied(
                "p=pkill; false && p=echo; f=-x; true && f=-f; t=foo; true && t=kirocrew; $p $f $t"
            )
            is not None
        )
        many = "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
        assert is_denied(many + "x=kirocrew; false && x=echo; $x token") is not None
        assert is_denied(many + "x=echo; false && x=kirocrew; $x token") is not None
        assert is_denied(many + "v=token; false && v=doctor; kirocrew $v") is not None
        # Folding the choices past a cap onto one shared bit was a bypass: three
        # filler guards pushed the program and the verb onto that bit, whose
        # all-prior and all-new readings never pair the prior program with the new
        # verb (found in review).  Filler names that are never expanded again are
        # not choices at all; expanded ones sit in their own group.
        pair = "x=kirocrew; false && x=echo; v=doctor; true && v=token; "
        fill = "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; "
        assert is_denied(fill + pair + "$x $v") is not None
        assert is_denied(fill + pair + "echo $a $b $c; $x $v") is not None
        assert is_denied(fill + pair + "echo $a $b $c ; $x $v") is not None
        assert is_denied(fill + pair + "y=$v; $x $y") is not None
        assert is_denied(fill + pair + "eval '$x $v'") is not None
        assert is_denied(fill + pair + 'bash -c "$x $v"') is not None
        assert (
            is_denied(fill + "p=kiro; false && p=ec; q=ho; true && q=crew; $p$q token") is not None
        )
        assert (
            is_denied(fill + "x=bash; false && x=echo; f=-n; true && f=-c; $x $f 'kirocrew token'")
            is not None
        )
        # Fillers whose values are protected are still just choices in their own group.
        loud = "a=kirocrew; false && a=echo; b=kirocrew; false && b=echo; c=kirocrew; false && c=echo; "
        assert is_denied(loud + pair + "echo $a $b $c ; $x $v") is not None
        # A group past the cap FOLDS to allowed when every value is inert; the cap is
        # not a cliff that refuses ordinary many-flag scripts.  It reads fail-closed
        # only when a value could name a protected program or the mint verb, so a
        # pairing cannot hide behind filler guards.
        seven = "".join(f"{n}=1; false && {n}=2; " for n in "abcdefg")
        assert is_denied(seven + "echo $a $b $c $d $e $f $g") is None
        # ...but an over-cap group one of whose values IS protected still fails closed.
        seven_hot = (
            "".join(f"{n}=1; false && {n}=2; " for n in "abcdef") + "g=kirocrew; false && g=echo; "
        )
        assert is_denied(seven_hot + "$g token $a $b $c $d $e $f") is not None
        # Controls: within the cap, or across groups, harmless choices stay allowed.
        assert is_denied(seven + "echo $a $b $c $d $e $f") is None
        assert (
            is_denied(seven + "echo $a ; echo $b ; echo $c ; echo $d ; echo $e ; echo $f ; echo $g")
            is None
        )
        assert is_denied(fill + "x=doctor; false && x=status; echo $a $b $c ; kirocrew $x") is None
        assert (
            is_denied(fill + "x=kirocrew; false && x=echo; v=doctor; true && v=status; $x $v")
            is None
        )
        assert is_denied(seven + "kirocrew doctor") is None
        # The ``eval`` argument join runs to the end of the token list it is given;
        # given ALL readings at once it outgrew its bound and the joined publish was
        # dropped (found in review).  Each reading is walked on its own.
        three = "a=1 && a=2 ; echo $a ; b=1 && b=2 ; echo $b ; c=1 && c=2 ; echo $c ; "
        assert is_denied(three + "eval 'x=1; git' 'push origin main'") is not None
        assert is_denied(three + "eval 'kirocrew' 'token'") is not None
        assert is_denied(fill + "echo $a $b $c; eval 'x=1; git' 'push origin main'") is not None
        assert is_denied(three + "eval 'x=1; git' 'status'") is None
        # A group whose readings would expand past the volume budget is not walked:
        # it reads fail-closed too (the kernel refuses such a command line anyway).
        from kiro_crew.security.shell_normalizer import (
            _GUARDED_READING_VOLUME,
            _UNREADABLE_GUARDED_READING,
            _resolve_local_assignment_readings,
            normalize_shell_command,
        )

        six = "".join(f"{n}=1; false && {n}=2; " for n in "abcdef")
        wide = (
            "v="
            + "a" * (_GUARDED_READING_VOLUME // 128)
            + "; "
            + six
            + "echo $a $b $c $d $e $f $v $v $v"
        )
        readings = _resolve_local_assignment_readings(normalize_shell_command(wide))
        assert list(_UNREADABLE_GUARDED_READING) in readings
        assert len(readings) == 2
        slim = "v=" + "a" * 1024 + "; " + six + "echo $a $b $c $d $e $f $v $v $v"
        readings = _resolve_local_assignment_readings(normalize_shell_command(slim))
        assert list(_UNREADABLE_GUARDED_READING) not in readings
        assert len(readings) == 64
        # The budget is the COMMAND's, not each group's: every reading is one more
        # full rescan, and the group count is bounded only by the command's length,
        # so 300 one-choice groups under the scan ceiling each passed the per-group
        # check and together held the loop ~28 s (found in review).  Past 64 readings
        # in all the command reads fail-closed; 63 groups is the last that is read.
        crowd = "".join(f"v{i}=1; false && v{i}=2; echo $v{i}; " for i in range(64)) + "true"
        readings = _resolve_local_assignment_readings(normalize_shell_command(crowd))
        assert list(_UNREADABLE_GUARDED_READING) in readings
        assert is_denied(crowd) is not None
        fewer = "".join(f"v{i}=1; false && v{i}=2; echo $v{i}; " for i in range(63)) + "true"
        readings = _resolve_local_assignment_readings(normalize_shell_command(fewer))
        assert list(_UNREADABLE_GUARDED_READING) not in readings
        assert len(readings) == 64
        assert is_denied(fewer) is None
        # The aggregate volume budget is spent the same way: 63 groups of a value
        # each reading carries past the budget in all.
        heavy = "v=" + "a" * (_GUARDED_READING_VOLUME // 48) + "; " + fewer + "; echo $v"
        readings = _resolve_local_assignment_readings(normalize_shell_command(heavy))
        assert list(_UNREADABLE_GUARDED_READING) in readings
        # An empty argument (``""``, kept by ``shlex``) in a command with a guarded
        # choice: the further reading's shared-segment split indexed the empty
        # token's last character, raised, and the frame walk's catch-all dropped
        # every frame, so the mint ran unread (found in review).
        assert (
            is_denied('x=kirocrew; y=a || y=b; echo $y; kirocrew_unused=1; $x token ""') is not None
        )
        assert is_denied("x=kirocrew; y=a || y=b; echo $y; $x token ''") is not None
        assert is_denied("x=kirocrew; eval 'y=a || y=b; echo $y; $x token \"\"'") is not None
        assert is_denied('x=pkill; y=a || y=b; echo $y; $x -f kirocrew ""') is not None
        assert is_denied('x=echo; y=a || y=b; echo $y; $x token ""') is None
        assert is_denied('x=kirocrew; y=a || y=b; echo $y ""; $x doctor') is None
        from kiro_crew.security.shell_normalizer import _novel_segments

        assert _novel_segments(["a", "", ";", "b"], ["a", "", ";", "c", ""]) == ["c", ""]
        # ``|&`` is a pipe too: the left side runs in a subshell, so the prior is
        # read as well, at top level and inside a script (found in review).
        assert is_denied("v=doctor; v=token |& cat; kirocrew $v") is not None
        assert is_denied("v=token; v=doctor |& cat; kirocrew $v") is not None
        assert is_denied("v=token; eval 'v=doctor |& cat; kirocrew $v'") is not None
        assert is_denied("v=token; bash -c 'v=doctor |& cat; kirocrew $v'") is not None
        assert is_denied("v=doctor; v=status |& cat; kirocrew $v") is None
        # ``shlex`` drops the quotes, so ``'#x'`` (a command the prefix is scoped to)
        # and ``#x`` (a comment) arrive alike: both readings (found in review).
        assert is_denied("v=token; v=doctor '#x'; kirocrew $v") is not None
        assert is_denied("v=doctor; v=token '#x'; kirocrew $v") is not None
        assert is_denied("v=doctor; v=status '#x'; kirocrew $v") is None
        # ``NAME+=$p`` appends a tracked value, so the append co-references the
        # name it reads: matching ``=`` alone put ``q`` in its own group, the prior
        # program never met the new verb, and the mint ran unread (found in review).
        assert (
            is_denied("p=echo; true && p=kirocrew; q+=$p; v=doctor; true && v=token; $q $v")
            is not None
        )
        assert (
            is_denied("p=kirocrew; true && p=echo; q+=$p; v=doctor; true && v=token; $q $v")
            is not None
        )
        assert is_denied("p=echo; true && p=kirocrew; q+=$p; $q token") is not None
        assert is_denied("q=kiro; q+=crew; v=doctor; true && v=token; $q $v") is not None
        assert is_denied("p=echo; true && p=ls; q+=$p; v=doctor; true && v=token; $q $v") is None
        assert (
            is_denied("p=echo; true && p=kirocrew; q+=$p; v=doctor; true && v=status; $q $v")
            is None
        )
        # A VERB binding is as live as a program one inside a script too: in double
        # quotes the outer shell expands ``$v`` before the script's own assignment
        # runs (found in review).  Same policy as the program case above.
        assert is_denied('v=token; eval "v=doctor; kirocrew $v"') is not None
        assert is_denied("v=token; eval 'v=doctor; kirocrew $v'") is not None
        assert is_denied('v=token; bash -c "v=doctor; kirocrew $v"') is not None
        assert is_denied('v=doctor; eval "v=doctor; kirocrew $v"') is None
        assert is_denied('v=1; eval "v=2; echo $v"') is None
        # Each reading is charged at its OWN size: the base reading keeps every
        # short prior while an alternate takes the long guarded value, so a
        # base-sized charge let six 1.7 KB choices expanded 3390 times (140 MB
        # over 63 alternates) pass the 8 MB budget and run ~170 s (found in
        # review).  Past the budget the command reads fail-closed, in the first
        # alternates.
        long_six = "; ".join(f"{n}=1; true && {n}=" + "x" * 1700 for n in "abcdef") + "; "
        uses = " ".join(f"${n}" for n in "abcdef") + " "
        bulk = long_six + uses * ((20 * 1024 - len(long_six)) // len(uses))
        readings = _resolve_local_assignment_readings(normalize_shell_command(bulk))
        assert list(_UNREADABLE_GUARDED_READING) in readings
        assert len(readings) <= 10  # not 64: the budget is spent by the first few
        assert is_denied(bulk) is not None
        # Controls: mixed readings over harmless values stay allowed.
        assert is_denied("x=echo; false && x=kirocrew; v=1; true && v=2; $x $v") is None
        assert (
            is_denied("p=echo; false && p=ls; f=-x; true && f=-f; t=foo; true && t=bar; $p $f $t")
            is None
        )
        assert is_denied(many + "x=echo; false && x=ls; $x token") is None
        # Controls: an unguarded reassignment DID run, and a guarded one over a
        # value that mints nothing stays allowed.
        assert is_denied("v=token; v=doctor; kirocrew $v") is None
        assert is_denied("v=doctor; false && v=status; kirocrew $v") is None
        assert is_denied("x=doctor; eval 'false && x=status; kirocrew $x'") is None
        # A guarded reassignment of a protected binding is read BOTH ways: the
        # prior may still run, and the new value may be a shell whose payload
        # the walk must descend (``x=<cli> && x=bash`` always runs the right side).
        assert is_denied("x=kirocrew && x=bash; $x -c 'kirocrew token'") is not None
        assert is_denied("x=kirocrew || x=bash; $x -c 'kirocrew token'") is not None
        assert is_denied("x=kirocrew; true && x=bash; $x -c 'kirocrew token'") is not None
        assert is_denied("x=kirocrew; x=bash | true; $x -c 'kirocrew token'") is not None
        assert is_denied("x=kirocrew && x=bash; $x token") is not None
        assert is_denied("x=kirocrew && x=bash; $x -c 'echo hi'") is None
        assert is_denied("x=ls && x=bash; $x -c 'echo hi'") is None
        assert is_denied("x=kirocrew && x=echo; $x doctor") is None
        assert is_denied("x=kirocrew y=1; $x token") is not None
        assert is_denied('X="a b";Y=kirocrew;$Y doctor') is None
        # One false-positive control per class: a leading run that rebinds to a
        # harmless program, a subshell-scoped reassignment ahead of a verb that
        # mints nothing, and a guarded kill program aimed at another target.
        assert is_denied("x=kirocrew; bash -c 'y=1 x=echo; $x hello'") is None
        assert is_denied("y=1 x=echo; $x hello") is None
        assert is_denied("x=kirocrew; eval 'x=foo | true; $x doctor'") is None
        assert is_denied("x=echo | true; $x hello") is None
        assert is_denied("x=pkill || x=echo; $x -f other-app") is None
        assert is_denied("x=pkill; x=echo; $x -f kirocrew") is None
        # An unguarded reassignment followed by ``||`` DID run: the shell's value.
        assert is_denied("x=pkill; x=echo || true; $x -f kirocrew") is None
        # A redirection or a comment after a bare assignment is not a command
        # word: the assignment stays persistent, as on main.
        for tail in (">/dev/null", "2>/dev/null", ">>log", "<in", "&>out", "# note"):
            assert is_denied(f"t=token {tail}; kirocrew $t") is not None, tail
        assert is_denied("x=kirocrew >/dev/null; $x token") is not None
        assert is_denied("x=kirocrew; x=foo true >/dev/null; $x token") is not None
        # An APPEND after a bare assignment run is not a command word either, so the
        # run has NO command and bash persists both assignments -- ``v=token`` must
        # replace the binding, as on main.  ``run_end`` used ``_LOCAL_ASSIGN_RE`` and
        # stopped at the append, so the run read as a prefix scoped to ``A+=b`` and the
        # mint binding went unreplaced (found in review; the verb spelling had no
        # ``_is_mint_verb`` rescue the program spelling got).
        assert is_denied("v=doctor; v=token A+=b; kirocrew $v") is not None
        assert is_denied("x=echo; x=kirocrew A+=b; $x token") is not None
        # A genuine prefix assignment before a real command word stays scoped to it.
        assert is_denied("X=foo A+=b make") is None
        assert is_denied("PATH+=/x:/y ls -la") is None
        # A prefix that is the FIRST binding of its name is inherited by the
        # command it prefixes, so it is recorded; only a prefix that would
        # replace a binding is skipped.
        assert is_denied("t=token bash -c 'kirocrew $t'") is not None
        assert is_denied("t=token eval 'kirocrew $t'") is not None
        assert is_denied("t=token kirocrew $t") is not None
        assert is_denied("t=doctor bash -c 'kirocrew $t'") is None
        # An argument spelled ``y=pkill`` after the command is not a binding, so
        # the prefix before it is still a prefix.
        assert is_denied("x=kirocrew; eval 'x=foo true y=pkill; $x token'") is not None
        assert is_denied("x=kirocrew; x=foo true y=pkill; $x token") is not None
        # An unquoted use of a value that holds whitespace is word-split, so the
        # value's first word is the program that runs -- at top level, guarded,
        # subshell-scoped, and inside a script the outer frame reaches into.
        assert is_denied('x="kirocrew -v"; $x token') is not None
        assert is_denied("x='kirocrew -v'; $x token") is not None
        assert is_denied('false || x="kirocrew -v"; $x token') is not None
        assert is_denied('x="kirocrew -v" | true; $x token') is not None
        assert is_denied('x="pkill -f"; $x kirocrew') is not None
        assert is_denied("x=foo; eval 'false || x=\"kirocrew -v\"; $x token'") is not None
        assert is_denied('x="ls -la"; $x /tmp') is None
        # ``$IFS`` is a word separator too, in the use itself or in the value: the
        # expanded use is split there (found in review: the raw rules read
        # ``kirocrew${IFS}token``, the resolver's expansion of ``$x`` did not).
        for use in ("$x${IFS}token", "${x}${IFS}token", "$x$IFS token", "$x${ifs}token"):
            assert is_denied(f"x=kirocrew; {use}") is not None, use
            assert is_denied(f"x=kirocrew;{use}") is not None, use
            assert is_denied(f"bash -c 'x=kirocrew;{use}'") is not None, use
            assert is_denied(f"eval 'x=kirocrew;{use}'") is not None, use
        assert is_denied("x=token; kirocrew${IFS}$x") is not None
        assert is_denied("x=kirocrew; $x${IFS}doctor") is None
        assert is_denied("x=kirocrew; echo $x${IFS}token") is None
        assert is_denied("x=ls; $x${IFS}-la") is None
        # An ESCAPED space is part of the word (``kirocrew token`` is one program).
        assert is_denied("bash -c 'x=kirocrew;$x\\ token'") is None
        # A prefix value spelled through a variable is read expanded, and a
        # protected prefix value binds whatever it prefixes.
        assert is_denied("x=echo; y=kirocrew; x=$y export x; $x token") is not None
        assert is_denied("x=echo; x=kirocrew readonly x; $x token") is not None
        assert is_denied("x=echo; y=kirocrew; eval 'x=$y export x; $x token'") is not None
        assert is_denied("x=echo; y=kirocrew; x=$y true; $x token") is not None
        assert is_denied("x=echo; x=ls export x; $x -la") is None
        # A builtin is a command word: bash scopes the prefix to it, so the binding
        # before it stands -- for the regular builtins (``local``, ``declare``,
        # ``typeset``, ``source``), which never persist a prefix, and for the special
        # ones, where the scoped reading is the one that refuses.
        for builtin in (
            "local y",
            "declare y",
            "typeset y",
            "source /dev/null",
            "export y",
            ". /dev/null",
        ):
            assert is_denied(f"x=kirocrew; x=echo {builtin}; $x token") is not None, builtin
            assert is_denied(f"x=kirocrew; eval 'x=echo {builtin}; $x token'") is not None, builtin
        assert is_denied("x=ls; x=echo local y; $x -la") is None
        # The outer frame's transformed and indirect uses reach into a script too.
        assert is_denied("k=kirocrew; eval 'true; ${k:0} token'") is not None
        assert is_denied("k=kirocrew; eval 'true; ${k^^} token'") is not None
        assert is_denied("n=k; k=kirocrew; eval 'true; ${!n} token'") is not None
        # ``eval`` joins its arguments; the joined frame spans the whole token and
        # its pieces, each read both ways after a guarded reassignment, and is
        # still walked.
        assert is_denied("eval 'x=1; kirocrew' token") is not None
        assert is_denied("eval 'x=1; git' 'push origin main'") is not None
        for filler in (23, 60, 400):
            script = (
                "x=kirocrew&&x=sh;echo $x; eval 'a=" + "f" * filler + "; git' 'push origin main'"
            )
            assert is_denied(script) is not None, filler
            assert (
                is_denied("x=kirocrew&&x=sh;echo $x; eval 'a=" + "f" * filler + "; git' 'status'")
                is None
            )
        # Every piece the join repeats costs one space the source never carried, so
        # a long run of separators is still inside the bound (a padded script was
        # dropped as over-long, and the publish it carried was allowed).
        assert is_denied("eval 'x=1; " + ":; " * 40 + "git' 'push origin main'") is not None
        assert is_denied("eval 'x=1; " + ":; " * 40 + "echo' 'push origin main'") is None
        # The glued spelling of a guarded reassignment reads like the spaced one.
        assert is_denied("x=kirocrew||x=echo;$x token") is not None
        assert is_denied("x=kirocrew&&x=echo;$x token") is not None
        # A multiword value used as an ARGUMENT stays one word -- also after an
        # assignment-shaped argument (found in review).
        assert is_denied('m="fix kirocrew token handling"; git commit -m "$m"') is None
        assert is_denied('m="kirocrew token"; echo "$m"') is None
        assert is_denied('x="kirocrew token"; make CFLAGS=-O2 $x') is None
        assert is_denied('x="kirocrew token"; true; y=1 $x') is not None
        assert is_denied('x="kirocrew token"; y=1 $x') is not None
        # An APPEND in the prefix run is a leading assignment too: the use after it
        # is still in command position and a multiword value is word-split (found
        # in review: read with the plain spelling only, the append hid the command
        # word and the mint ran).  An append never REPLACES an outer binding.
        assert is_denied("bash -c 'x=\"kirocrew -v\"; A+=foo $x token'") is not None
        assert is_denied('x="kirocrew -v"; A+=foo $x token') is not None
        assert is_denied('x="kirocrew -v"; A+=foo B=bar $x token') is not None
        assert is_denied('x="kirocrew -v"; A=foo B+=bar $x token') is not None
        assert is_denied("x=kirocrew; eval 'x+=\" -v\"; $x token'") is not None
        assert is_denied("x=kiro; eval 'x+=crew; $x token'") is not None
        assert is_denied('x="echo -n"; A+=foo $x hi') is None
        assert is_denied("A+=foo make CFLAGS=-O2") is None
        # A guarded or subshell-scoped APPEND is a choice read both ways, as the
        # ``=`` spelling already was (found in review: the append took the only
        # reading and ``kirocrewzzz`` hid the mint).
        assert is_denied("q=kirocrew; false && q+=zzz; $q token") is not None
        assert is_denied("q=kirocrew; true && q+=zzz; $q token") is not None
        assert is_denied("q=kirocrew; q+=zzz | true; $q token") is not None
        assert is_denied("q=kirocr; false && q+=ew; $q token") is not None
        assert is_denied("q=kirocrew; q+=zzz; $q token") is None
        assert is_denied("q=echo; false && q+=zzz; $q token") is None
        # The body of a compound command is guarded by its test or pattern: an
        # assignment after ``then``/``do``/``else``/``elif``/``{`` or after a
        # ``case`` pattern is read both ways too (found in review: the single
        # reading took the body's value and the mint bash ran was allowed).
        assert is_denied("x=kirocrew; if false; then x=echo; fi; $x token") is not None
        assert is_denied("x=kirocrew; if true; then x=echo; else x=ls; fi; $x token") is not None
        assert is_denied("x=kirocrew; while false; do x=echo; done; $x token") is not None
        assert is_denied("x=kirocrew; { x=echo; }; $x token") is not None
        assert is_denied("x=kirocrew; eval 'if false; then x=echo; fi; $x token'") is not None
        assert is_denied("x=kirocrew; eval 'case q in z) x=echo ;; esac; $x token'") is not None
        assert is_denied("x=echo; if false; then x=echo; fi; $x token") is None
        assert is_denied("x=echo; { x=echo; }; $x token") is None
        assert is_denied("x=echo; if false; then x=ls; fi; $x token") is None
        # ... and the guard is sticky over the WHOLE body, not the first statement
        # only (found in review: ``x=echo`` after ``y=1`` followed ``;``, not
        # ``then``, and the single reading took it while bash skipped the body).
        for body in (
            "if false; then y=1; x=echo; fi",
            "if false; then y=1; z=2; x=echo; fi",
            "if false; then :; else y=1; x=echo; fi",
            "if false; then :; elif false; then y=1; x=echo; fi",
            "while false; do y=1; x=echo; done",
            "until true; do y=1; x=echo; done",
            "for i in 1; do y=1; x=echo; done",
            "{ y=1; x=echo; }",
            "case q in q) y=1; x=echo;; esac",
            "case q in z) :;; q) y=1; x=echo;; esac",
            "if false; then y=1; x+=zzz; fi",
            "if false; then if false; then y=1; fi; x=echo; fi",
        ):
            assert is_denied(f"x=kirocrew; {body}; $x token") is not None, body
            assert is_denied(f"x=kirocrew; eval '{body}; $x token'") is not None, body
            assert is_denied(f"x=kirocrew; bash -c '{body}; $x token'") is not None, body
            verb_body = body.replace("x=echo", "v=doctor").replace("x+=zzz", "v+=zzz")
            assert is_denied(f"v=token; {verb_body}; kirocrew $v") is not None, body
        assert is_denied("x=kirocrew;if false;then y=1;x=echo;fi;$x token") is not None
        # After the closer the assignment is unconditional again; a body that never
        # touches the name changes nothing; a keyword echoed as DATA opens no body.
        assert is_denied("x=kirocrew; if false; then y=1; fi; x=echo; $x token") is None
        assert is_denied("x=echo; if false; then y=1; x=doctor; fi; $x token") is None
        assert is_denied("x=gcc; if false; then y=1; x=clang; fi; $x main.c") is None
        assert is_denied("x=kirocrew; echo if; x=echo; $x token") is None
        assert is_denied('x=kirocrew; echo "for the record"; x=echo; $x token') is None
        assert is_denied("x=kirocrew; if false; then echo fi; x=echo; fi; $x token") is not None
        # ... nor does a closer GLUED inside a quoted argument: ``shlex`` hands
        # ``'a;fi'`` over as the bare token ``a;fi``, and closing the body on it
        # read the reassignment after it as unguarded (found in review).
        for body in (
            "if false; then echo 'a;fi'; x=echo; fi",
            "if false; then echo 'a;fi;'; x=echo; fi",
            "if false; then echo a\\;fi; x=echo; fi",
            "while false; do echo 'a;done'; x=echo; done",
            "{ echo 'a;}'; x=echo; }",
        ):
            assert is_denied(f"x=kirocrew; {body}; $x token") is not None, body
        assert is_denied("x=kirocrew; if false; then echo 'a;fi'; fi; x=echo; $x token") is None
        assert is_denied("echo 'a;fi'; ls") is None
        # A use glued to its separator ends its simple command in the grouping too:
        # seven independent guards with no self reference are seven one-choice
        # groups, not one unreadable group (found in review: refused on the glued
        # spelling, allowed on the spaced one).
        seven = "; ".join(f"{n}=1; true && {n}=2" for n in "abcdefg")
        assert is_denied(seven + "; " + "; ".join(f"echo ${n}" for n in "abcdefg")) is None
        assert is_denied(seven + "; " + ";".join(f"echo ${n}" for n in "abcdefg")) is None
        # A boundary token carrying NO ``$`` (``q;echo``) still closes the segment, so
        # the seven guards stay seven one-choice groups rather than union into one
        # unreadable group (found in review: the ``$`` test skipped the boundary).
        assert is_denied(seven + "; " + ";".join(f"echo ${n} q" for n in "abcdefg")) is None
        # All seven in ONE argv are one over-cap group; inert it folds to allowed, but
        # with a protected value among them it fails closed.
        assert is_denied(seven + "; echo " + " ".join(f"${n}" for n in "abcdefg")) is None
        hot = "; ".join(f"{n}=1; true && {n}=2" for n in "abcdef") + "; g=kirocrew; true && g=echo"
        assert is_denied(hot + "; $g token " + " ".join(f"${n}" for n in "abcdef")) is not None
        # A protected SIBLING in a prefix run does not make the other name the
        # script's own binding: the outer protected value still reaches the use
        # -- and so does a persistent run, since the outer value is protected.
        assert is_denied("x=kirocrew; eval 'x=echo y=kirocrew true; $x token'") is not None
        assert is_denied("x=kirocrew; eval 'x=echo y=foo true; $x token'") is not None
        assert is_denied("x=kirocrew; eval 'x=echo y=kirocrew; $x token'") is not None
        assert is_denied("x=ls; eval 'x=echo y=kirocrew; $x token'") is None
        # ``case`` clause terminators are command boundaries, so a reassignment in
        # a clause body persists.
        for term in (";;", ";&", ";;&"):
            assert (
                is_denied(f"t=doctor; case q in q) t=token {term} esac; kirocrew $t") is not None
            ), term
        # ... and the clause body is guarded by its pattern, so the prior is read too.
        assert is_denied("x=kirocrew; case q in q) x=echo ;; esac; $x token") is not None
        assert is_denied("x=echo; case q in q) x=echo ;; esac; $x token") is None
        # A word GLUED to the pattern's ``)`` is its own word: the use ``x)$x`` and
        # the assignment ``x)x=<cli>`` were read as part of the pattern (found in
        # review: ``case x in x)$x token;;esac`` ran the mint).
        for glued in (
            "x=kirocrew; case x in x)$x token;;esac",
            "x=kirocrew; case x in x)$x token;; esac",
            "x=kirocrew; case x in *)$x token;;esac",
            "bash -c 'x=kirocrew; case x in x)$x token;;esac'",
            "eval 'x=kirocrew; case x in x)$x token;;esac'",
            "v=token; case x in x)kirocrew $v;;esac",
            "x=echo; case x in x)x=kirocrew;;esac; $x token",
            "x=echo; eval 'case x in x)x=kirocrew;;esac; $x token'",
            "x=kirocrew; case x in x)x=echo;;esac; $x token",
        ):
            assert is_denied(glued) is not None, glued
        assert is_denied("case x in x)echo hi;;esac") is None
        assert is_denied("x=ls; case x in x)$x -la;;esac") is None
        assert is_denied("x=kirocrew; case x in x)$x doctor;;esac") is None
        assert is_denied("f(){ echo hi; }; f") is None
        assert is_denied("echo $(date)x") is None
        # A function definition's glued ``{`` opens a body: the reassignment in it
        # runs when the function is called, so it is read both ways (found in
        # review: ``f(){ x=kirocrew; }; f; $x token`` inside a script minted).
        for spelled in (
            "x=echo; bash -c 'f(){ x=kirocrew; }; f; $x token'",
            "x=echo; eval 'f(){ x=kirocrew; }; f; $x token'",
            "x=echo; bash -c 'f() { x=kirocrew; }; f; $x token'",
            "x=echo; bash -c 'function f { x=kirocrew; }; f; $x token'",
            "x=echo; bash -c 'f(){ y=1; x=kirocrew; }; f; $x token'",
            "x=echo; bash -c '{ x=kirocrew; }; $x token'",
            "v=doctor; bash -c 'f(){ v=token; }; f; kirocrew $v'",
            "x=echo; f(){ x=kirocrew; }; f; $x token",
        ):
            assert is_denied(spelled) is not None, spelled
        assert is_denied("x=echo; bash -c 'f(){ x=ls; }; f; $x -la'") is None
        assert is_denied("x=echo; bash -c 'f(){ x=kirocrew; }; $x doctor'") is None
        # A script that does not OPEN with an assignment still reads its own
        # bindings ahead of the outer frame's.
        assert is_denied("x=foo; eval 'true; x=kirocrew; $x token'") is not None
        assert is_denied("x=foo; bash -c 'true; x=kirocrew; $x token'") is not None
        assert is_denied("x=foo; eval 'true && x=kirocrew; $x token'") is not None
        assert is_denied("x=kirocrew; eval 'true; $x token'") is not None
        assert is_denied("x=foo; eval 'true; x=echo; $x hello'") is None
        # A separator INSIDE a quote the script still carries is data: the text after
        # it is the rest of a word, not an assignment, so the outer binding still
        # reaches the use -- in the whole-script frame and in the glued pieces.
        assert is_denied('x=kirocrew; eval \'printf "%s" "; x=echo"; $x token\'') is not None
        assert is_denied('x=kirocrew; bash -c \'printf "%s" "; x=echo"; $x token\'') is not None
        assert is_denied("x=kirocrew; eval \"printf '%s' '; x=echo'; \\$x token\"") is not None
        assert is_denied("x=pkill; eval 'echo \"; x=echo\"; $x -f kirocrew'") is not None
        assert is_denied('x=kirocrew; eval \'y=1;printf "%s" ";x=echo"\'; $x token') is not None
        # An UNCLOSED quote reads the rest of the script as data.
        assert is_denied("x=kirocrew; eval 'echo \"; x=echo; $x token'") is not None
        # A quote that survives ``shlex`` in a BARE token (no whitespace) was escaped
        # and is literal data: the separators beside it are real, so the assignment
        # they carry is read (the glued spelling and the spaced one alike).
        assert is_denied('q=\\";x=kirocrew;\\";$x token') is not None
        assert is_denied('q=\\";x=kirocrew;\\"; $x token') is not None
        assert is_denied("q=\\';x=kirocrew;\\';$x token") is not None
        assert is_denied('q=\\"; x=kirocrew; \\"; $x token') is not None
        # ... and a real reassignment beside such a literal quote is a reassignment.
        assert is_denied('x=kirocrew; q=\\";x=echo;\\"; $x token') is None
        assert is_denied('echo \\"a;b\\"; x=ls; $x token') is None
        # A quoted separator in ordinary data, and a REAL reassignment after one.
        assert is_denied('m="a; b"; eval \'printf "%s" "$m"; echo ok\'') is None
        assert is_denied('x=1;eval \'printf "%s" "a;b"\';echo $x') is None
        assert is_denied('x=ls; eval \'x=echo; printf "%s" "; a"; $x token\'') is None
        # An assignment-shaped ARGUMENT is its command's data unless that command
        # runs it, so it is one more choice read both ways (found in review: the
        # pieces of the quoted operand overwrote the outer binding).  Both
        # spellings, quoted and bare, and the append.
        assert is_denied("x=kirocrew; echo 'x=echo; harmless'; $x token") is not None
        assert is_denied('x=kirocrew; echo "x=echo; harmless"; $x token') is not None
        assert is_denied("x=kirocrew;echo 'x=echo; harmless';$x token") is not None
        assert is_denied("x=kirocrew; echo x=echo; $x token") is not None
        assert is_denied("x=kirocrew; make x=echo; $x token") is not None
        assert is_denied("x=kirocrew; echo 'x+=zzz; harmless'; $x token") is not None
        assert is_denied("x=kirocrew; echo x+=zzz; $x token") is not None
        assert is_denied("x=kirocrew; eval 'x=echo; true'; $x token") is not None
        assert is_denied("x=kirocrew; bash -c 'x=echo; true'; $x token") is not None
        assert is_denied("v=token; echo 'v=doctor; harmless'; kirocrew $v") is not None
        # ... the new value is still a reading, as before.
        assert is_denied("x=echo; echo 'x=kirocrew; harmless'; $x token") is not None
        assert is_denied("x=echo; echo x=kirocrew; $x token") is not None
        # A declaration builtin's argument IS the shell's own binding, and a
        # reassignment in command position is not a choice.
        assert is_denied("x=kirocrew; export x=echo; $x token") is None
        assert is_denied("x=kirocrew; declare x=echo; $x token") is None
        assert is_denied("x=kirocrew; local x=echo; $x token") is None
        assert is_denied("x=kirocrew; true; x=echo; $x token") is None
        assert is_denied("x=kirocrew; y=1 x=echo; $x token") is None
        assert is_denied("make CFLAGS=-O2 target") is None
        assert is_denied("echo 'x=kirocrew; harmless'; $x doctor") is None
        assert is_denied("git commit -m 'x=1; done' && echo ok") is None
        # An append INSIDE a whole script extends the outer value the script's
        # own uses read (found in review: the tail was dropped, and a script that
        # OPENED with an append was read as one append whose tail was the rest
        # of the script).  Guarded, it is a choice read both ways.
        assert is_denied("x=kiro; eval 'x+=crew; $x token'") is not None
        assert is_denied("x=kiro; eval 'x+=crew;$x token'") is not None
        assert is_denied("x=kiro; eval 'true; x+=crew; $x token'") is not None
        assert is_denied("x=kiro; bash -c 'x+=crew; $x token'") is not None
        assert is_denied("v=tok; eval 'v+=en; kirocrew $v'") is not None
        assert is_denied("x=kiro; eval 'false && x+=crew; $x token'") is not None
        assert is_denied("x=kirocrew; eval 'false && x+=zzz; $x token'") is not None
        assert is_denied("x=kirocrew; eval 'x+=\" -v\"; $x token'") is not None
        assert is_denied("x=echo; eval 'x+=crew; $x token'") is None
        assert is_denied("x=kiro; eval 'x+=s; $x token'") is None
        assert is_denied("x=a; eval 'x+=b; echo $x'") is None
        assert is_denied("eval 'x+=crew; $x token'") is None
        # An operator INSIDE a use's braces is no separator: the name still has a
        # group, so its guarded choice is still read both ways (found in review:
        # the pieces lost the name and only the prior was read).
        for use in ("${v#|}", "${v%|}", "${v/|/}", "${v#;}", "${v#&}"):
            assert is_denied(f"v=doctor; true && v=token; kirocrew {use}") is not None, use
        assert is_denied("x=echo; true && x=kirocrew; ${x#|} token") is not None
        assert is_denied("v=doctor; kirocrew ${v#|}") is None
        assert is_denied("v=a; true && v=b; echo ${v#|}") is None
        # ...and an operator inside an expansion is no command boundary between TWO
        # co-referenced guarded names either, so they stay in one group and the mint
        # pairing is enumerated (found in review: ``$x ${v#;}`` split ``x`` and ``v``
        # apart, so ``kirocrew token`` was never read while bash expands ``${v#;}``).
        for use in ("${v#;}", "${v#&}", "${v%|}", "${v/;/}"):
            assert (
                is_denied(f"x=echo; true && x=kirocrew; v=doctor; true && v=token; $x {use}")
                is not None
            ), use
        assert is_denied("x=ls; true && x=cat; v=doctor; true && v=hello; $x ${v#;}") is None
        # A DEFAULT/alternate expansion (``${d:-a&b}``) was excluded from the masking
        # regex, so its interior separator split the group apart and the mint pairing
        # went unread (found in review); the default form masks its interior too.
        for use in ("${d:-a&b}", "${d:+a&b}"):
            assert (
                is_denied(f"x=echo; true && x=kirocrew; v=doctor; true && v=token; $x {use} $v")
                is not None
            ), use
        assert is_denied("x=ls; true && x=cat; v=doctor; true && v=hi; $x ${d:-a&b} $v") is None
        # A further reading keeps the whole PIPELINE its novel command sits in, so
        # the pipe into an evaluator is still read (found in review: the reading
        # was cut to the command alone and the evaluator never saw it) -- and a
        # pipe joins its two sides' names into one group, so two choices across
        # it are paired.
        assert is_denied('v=nope; true && v=kirocrew; echo "$v token" | sh') is not None
        assert is_denied('v=nope; true && v=kirocrew; echo "$v token" | bash') is not None
        assert is_denied('v=nope; true && v=kirocrew; echo "$v token" | xargs') is not None
        assert (
            is_denied('v=nope; true && v=kirocrew; echo "$v token" | xargs -I{} sh -c {}')
            is not None
        )
        assert (
            is_denied('v=nope; true && v=kirocrew; x=cat; true && x=sh; echo "$v token" | $x')
            is not None
        )
        assert is_denied('v=nope; true && v=kirocrew; echo "$v doctor" | sh') is None
        assert is_denied('v=nope; true && v=ls; echo "$v token" | sh') is None
        assert is_denied('v=nope; true && v=kirocrew; echo "$v token" | cat') is None
        # ... and a pipe GLUED to the reading's last word is read as the operator it
        # spells, ``|&`` included (found in review: only a glued ``|`` was, so the
        # pipeline was flushed and ``sh`` dropped from the further reading).
        for glued in ('"$v token"|& sh', '"$v token"|&sh', '"$v token"| sh', '"$v token"|sh'):
            assert is_denied(f"v=nope; true && v=kirocrew; echo {glued}") is not None, glued
        assert is_denied('v=nope; true && v=kirocrew; echo "$v token"|& cat') is None
        assert is_denied('v=nope; true && v=doctor; echo "$v hello"|& sh') is None
        # ``||`` is read as ``main`` reads it -- a pipe, conservatively -- so the
        # reading keeps ``|| sh`` and the verdict is unchanged.
        assert is_denied('v=nope; true && v=kirocrew; echo "$v token"|| sh') is not None
        assert is_denied('v=nope; true && v=kirocrew; echo "$v token" || sh') is not None
        assert is_denied('v=nope; true && v=kirocrew; echo "$v token"&& sh') is None
        # Two guards SPELLED alike are two choices, never one test (found in review:
        # the reader works on case-folded text, so ``$Path`` and ``$PATH`` are one
        # name here and two in bash; and a command between two ``$PWD`` tests, or a
        # ``source``/``eval``, rewrites what the second reads).  Tying them folded
        # away the mixed reading that pairs the prior program with the new verb.
        for guards in (
            ('[ -n "$Path" ]', "", '[ -n "$PATH" ]'),
            ('[ -n "$A" ]', "", '[ -n "$A" ]'),
            ('[ "$PWD" = /tmp ]', "cd /tmp; ", '[ "$PWD" = /tmp ]'),
            ('[ -n "$A" ]', "source rc; ", '[ -n "$A" ]'),
            ('[ -n "$A" ]', 'eval "$cfg"; ', '[ -n "$A" ]'),
            ('[ -n "$OLDPWD" ]', "cd ..; ", '[ -n "$OLDPWD" ]'),
            ('[ -n "$_" ]', "", '[ -n "$_" ]'),
            ('[ -n "$A" ]', "A=1; ", '[ -n "$A" ]'),
            ('[ -n "$A" ]', ": ${A:=1}; ", '[ -n "$A" ]'),
            ('test -n "$A"', "", 'test -n "$A"'),
            ("[[ -n $A ]]", "", "[[ -n $A ]]"),
        ):
            first, between, second = guards
            assert (
                is_denied(
                    f"x=kirocrew; {first} && x=echo; {between}v=doctor; {second} && v=token; $x $v"
                )
                is not None
            ), guards
            assert (
                is_denied(
                    f"x=echo; {first} && x=kirocrew; {between}v=doctor; {second} && v=token; $x $v"
                )
                is not None
            ), guards
        # ... and two guarded harmless choices under one spelling stay allowed: four
        # readings, none a protected pairing.
        assert (
            is_denied('x=gcc; [ -n "$A" ] && x=clang; v=-O2; [ -n "$A" ] && v=-O3; $x $v main.c')
            is None
        )
        assert (
            is_denied('x=gcc; [ -n "$A" ] && x=clang; cd /tmp; v=-O2; [ -n "$A" ] && v=-O3; $x $v')
            is None
        )
        # Seven guarded names meeting in one argv are past the cap however the guards
        # are spelled -- seven distinct tests, or seven defaults under two -- but when
        # every value is inert (ordinary build/deploy flags) the group FOLDS to allowed;
        # it fails closed only when a value could name a protected program or the mint
        # verb.
        seven_tests = (
            "; ".join(f'{n}=a; [ -n "$T{i}" ] && {n}=b' for i, n in enumerate("abcdefg"))
            + "; ./build.sh "
            + " ".join(f"${n}" for n in "abcdefg")
        )
        assert is_denied(seven_tests) is None
        toolchain = (
            'cc=gcc; [ -n "$USE_CLANG" ] && cc=clang; cxx=g++; [ -n "$USE_CLANG" ] && cxx=clang++; '
            'ar=ar; [ -n "$LLVM" ] && ar=llvm-ar; ld=ld; [ -n "$LLVM" ] && ld=lld; '
            'nm=nm; [ -n "$LLVM" ] && nm=llvm-nm; strip=strip; [ -n "$LLVM" ] && strip=llvm-strip; '
            'ranlib=ranlib; [ -n "$LLVM" ] && ranlib=llvm-ranlib; '
            "./build.sh $cc $cxx $ar $ld $nm $strip $ranlib"
        )
        assert is_denied(toolchain) is None
        # ... however the seven guards are spelled: one compound body holding all
        # seven overrides, or one env test flipping seven deploy values (the lane's
        # rows; the cliff is the count of names meeting in one argv, not the guard).
        if_body = (
            "cc=gcc; cxx=g++; ar=ar; ld=ld; nm=nm; strip=strip; ranlib=ranlib; "
            'if [ -n "$LLVM" ]; then cc=clang; cxx=clang++; ar=llvm-ar; ld=lld; nm=llvm-nm; '
            "strip=llvm-strip; ranlib=llvm-ranlib; fi; ./build.sh $cc $cxx $ar $ld $nm $strip $ranlib"
        )
        assert is_denied(if_body) is None
        deploy = (
            'ns=default; [ -n "$PROD" ] && ns=prod; rep=1; [ -n "$PROD" ] && rep=3; '
            'img=app:dev; [ -n "$PROD" ] && img=app:stable; cpu=100m; [ -n "$PROD" ] && cpu=500m; '
            'mem=128Mi; [ -n "$PROD" ] && mem=512Mi; port=8080; [ -n "$PROD" ] && port=443; '
            'tls=off; [ -n "$PROD" ] && tls=on; ./deploy.sh $ns $rep $img $cpu $mem $port $tls'
        )
        assert is_denied(deploy) is None
        # The same seven-name shape fails closed the moment one value could mint: a
        # name bound to the CLI with a ``token`` use among the args.
        toolchain_hot = (
            'cc=gcc; [ -n "$USE_CLANG" ] && cc=clang; cxx=g++; [ -n "$USE_CLANG" ] && cxx=clang++; '
            'ar=ar; [ -n "$LLVM" ] && ar=llvm-ar; ld=ld; [ -n "$LLVM" ] && ld=lld; '
            'nm=nm; [ -n "$LLVM" ] && nm=llvm-nm; strip=strip; [ -n "$LLVM" ] && strip=llvm-strip; '
            'cli=kirocrew; [ -n "$LLVM" ] && cli=echo; $cli token $cc $cxx $ar $ld $nm $strip'
        )
        assert is_denied(toolchain_hot) is not None
        # An over-cap group whose values are ENV VARS the command does not bind
        # ($CLANG_CC, $PROD_NS) resolves to nothing known, so it folds to allowed.
        var_toolchain = (
            'cc=gcc; [ -n "$USE_CLANG" ] && cc=$CLANG_CC; cxx=g++; [ -n "$USE_CLANG" ] && cxx=$CLANG_CXX; '
            'ar=ar; [ -n "$LLVM" ] && ar=$LLVM_AR; ld=ld; [ -n "$LLVM" ] && ld=$LLVM_LD; '
            'nm=nm; [ -n "$LLVM" ] && nm=$LLVM_NM; st=strip; [ -n "$LLVM" ] && st=$LLVM_ST; '
            'rl=ranlib; [ -n "$LLVM" ] && rl=$LLVM_RL; ./build.sh $cc $cxx $ar $ld $nm $st $rl'
        )
        assert is_denied(var_toolchain) is None
        # A bare mint verb passed to an inert program ($auth to ./run.sh) is not a mint.
        assert (
            is_denied(
                'auth=none; [ -n "$SEC" ] && auth=token; a=1; [ -n "$F" ] && a=2; b=1; [ -n "$F" ] && b=2; '
                'c=1; [ -n "$F" ] && c=2; d=1; [ -n "$F" ] && d=2; e=1; [ -n "$F" ] && e=2; '
                'g=1; [ -n "$F" ] && g=2; ./run.sh $auth $a $b $c $d $e $g'
            )
            is None
        )
        # ...but a value that RESOLVES through the command's own literals to the cli
        # still fails closed, even past the cap.
        assert (
            is_denied(
                'k=kirocrew; a=1; [ -n "$A" ] && a=2; b=1; [ -n "$A" ] && b=2; '
                'c=1; [ -n "$A" ] && c=2; d=1; [ -n "$A" ] && d=2; e=1; [ -n "$A" ] && e=2; '
                'x=$k; [ -n "$A" ] && x=y; $x token $a $b $c $d $e'
            )
            is not None
        )
        # Program-aware fold: six filler guards cannot hide a guarded self-subcommand
        # behind the cap when the cli is the program word -- the cli met by a guarded
        # operand fails closed however inert the values look.
        assert (
            is_denied(
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                "e=1; false && e=2; f=1; false && f=2; g=doctor; false && g=restart; "
                "kirocrew $g $a $b $c $d $e $f"
            )
            is not None
        )
        # A single filler-free guard on a cli operand is under the cap -- enumerated as
        # before: the subcommand reading denies, an inert reading allows.
        assert is_denied("v=doctor; false && v=restart; kirocrew $v") is not None
        assert is_denied("v=status; false && v=info; kirocrew $v") is None
        # An ssh-like verb reaching a guarded operand past the cap fails closed too.
        assert (
            is_denied(
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                "e=1; false && e=2; f=1; false && f=2; g=-V; false && g=$SELF; ssh $g $a $b $c $d $e $f"
            )
            is not None
        )
        # The program word is resolved through the command's literals: the cli reached
        # via a bound name (`$k` where `k=<cli>`) with a guarded operand fails closed.
        assert (
            is_denied(
                "k=kirocrew; a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; "
                "d=1; false && d=2; e=1; false && e=2; f=1; false && f=2; "
                "v=doctor; false && v=token; $k $v $a $b $c $d $e $f"
            )
            is not None
        )
        # A guarded value resolved through a reassigned name reads the LIVE binding, so
        # `g=$p` after `p=echo; p=pkill` sees pkill and the self-kill fails closed.
        assert (
            is_denied(
                "p=echo; p=pkill; g=safe; false && g=$p; a=1; false && a=2; b=1; false && b=2; "
                "c=1; false && c=2; d=1; false && d=2; e=1; false && e=2; $g -f kirocrew $a $b $c $d $e"
            )
            is not None
        )
        # An inert script folds however MANY names meet in it -- the volume estimate is
        # not charged against a folded over-cap group (15 names, all inert).
        assert (
            is_denied(
                "; ".join(f'n{i}=v{i}; [ -n "$P" ] && n{i}=w{i}' for i in range(15))
                + "; ./deploy.sh "
                + " ".join(f"$n{i}" for i in range(15))
            )
            is None
        )
        # An APPEND builds its value onto the live binding, so `g=pki; g+=ll` past the
        # cap resolves to `pkill` and the self-kill fails closed.
        assert (
            is_denied(
                "a=1; true && a=2; b=1; true && b=2; c=1; true && c=2; d=1; true && d=2; "
                "e=1; true && e=2; f=1; true && f=2; g=pki; true && g+=ll; $g -f kirocrew "
                "$a $b $c $d $e $f"
            )
            is not None
        )
        # The cli hidden behind an exec-wrapper (`env`/`sudo`/`timeout`/`xargs`) is seen:
        # any word of the command being the cli, with a guarded operand, fails closed.
        for wrapped in ("env kirocrew $v", "sudo kirocrew $v", "timeout 5 kirocrew $v"):
            assert (
                is_denied(
                    "a=1; true && a=2; b=1; true && b=2; c=1; true && c=2; d=1; true && d=2; "
                    "e=1; true && e=2; f=1; true && f=2; v=doctor; true && v=token; "
                    + wrapped
                    + " $a $b $c $d $e $f"
                )
                is not None
            ), wrapped
        # Two adjacent expansions with OPPOSITE guard outcomes assemble a protected
        # word (`$p$q` -> `kirocrew`) that neither per-value nor last-wins catches; the
        # fold considers both values of each guarded name, so it fails closed.
        assert (
            is_denied(
                "a=1; true && a=2; b=1; true && b=2; c=1; true && c=2; d=1; true && d=2; "
                "e=1; true && e=2; p=kiro; false && p=ec; q=ho; true && q=crew; $p$q token; "
                "echo $a $b $c $d $e"
            )
            is not None
        )
        # A guarded value naming a NESTED SHELL hides a `-c` payload from the floors; the
        # fold treats a nested-shell program value as fail-closed.
        assert (
            is_denied(
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                "e=1; false && e=2; f=1; false && f=2; g=true; false && g=bash; "
                "$g -c 'git push --force origin main' $a $b $c $d $e $f"
            )
            is not None
        )
        # A MULTI-WORD guarded value (`g="bash -c"`) runs its first field as the program;
        # the fold checks each whitespace field, so the nested shell is seen.
        assert (
            is_denied(
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                'e=1; false && e=2; f=1; false && f=2; g=true; false && g="bash -c"; '
                "$g 'git push --force origin main' $a $b $c $d $e $f"
            )
            is not None
        )
        # A PARAMETER-TRANSFORM expansion (`${g#x}`) references the same name; the fold
        # reads the name from every expansion form, so the self-subcommand is seen.
        assert (
            is_denied(
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                "e=1; false && e=2; f=1; false && f=2; g=doctor; false && g=restart; "
                "kirocrew ${g#x} ${a#x} ${b#x} ${c#x} ${d#x} ${e#x} ${f#x}"
            )
            is not None
        )
        # A TWO-HOP alias resolves to a fixpoint: `g=$m` where `m=$k` and `k=<cli>`
        # names the cli, so a one-hop resolve that stopped at `$m` must not fold the
        # group to allowed. Fails closed past the cap.
        assert (
            is_denied(
                "k=kirocrew; a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; "
                "d=1; false && d=2; e=1; false && e=2; f=1; false && f=2; "
                "m=$k; g=echo; true && g=$m; $g token $a $b $c $d $e $f"
            )
            is not None
        )
        # An UNTRACKED expansion drops (the shell removes an unset variable), so the
        # tracked halves of `$x$zz$q` glue into the cli; the empty candidate for an
        # untracked ref is enumerated, so the assembly fails closed past the cap.
        assert (
            is_denied(
                "x=kiro; q=crew; a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; "
                "d=1; false && d=2; e=1; false && e=2; f=1; false && f=2; g=1; false && g=2; "
                "$x$zz$q token $a $b $c $d $e $f $g"
            )
            is not None
        )
        # An EMPTY command substitution splices out (`kiro$()crew` -> `kirocrew`); the
        # word keeps its `$`, but `dangerous()` peels `$()` via program_basename, so it
        # is seen without a `"$" not in resolved` guard suppressing it.
        assert (
            is_denied(
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                "e=1; false && e=2; f=1; false && f=2; v=doctor; false && v=token; "
                "echo $a $b $c $d $e $f $v; kiro$()crew $v"
            )
            is not None
        )
        # A `${zz:-lit}` default runs `lit` when the name is unset; the untracked
        # default literal is enumerated as a candidate, so a mint spelled through it
        # fails closed past the cap.
        assert (
            is_denied(
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                "e=1; false && e=2; f=1; false && f=2; g=x; false && g=y; "
                "echo $a $b $c $d $e $f; ${zz:-kirocrew} token $g"
            )
            is not None
        )
        # ``git`` is anchored to a PUBLISH operand, not the bare program: a read-only
        # ``git status``/``git log`` assembled from an over-cap guarded group is allowed
        # (a polyglot release script selecting the vcs by a guarded name), while a
        # guarded publish operand past the cap still fails closed (found in review).
        assert (
            is_denied(
                'vcs=git; [ -n "$USE_HG" ] && vcs=hg; '
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                "e=1; false && e=2; f=1; false && f=2; $vcs status $a $b $c $d $e $f"
            )
            is None
        )
        assert (
            is_denied(
                'vcs=git; [ -n "$USE_HG" ] && vcs=hg; '
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                "e=1; false && e=2; f=1; false && f=2; $vcs log $a $b $c $d $e $f"
            )
            is None
        )
        assert (
            is_denied(
                "p=echo; false && p=git; "
                "a=1; false && a=2; b=1; false && b=2; c=1; false && c=2; d=1; false && d=2; "
                "e=1; false && e=2; f=1; false && f=2; $p push origin main $a $b $c $d $e $f"
            )
            is not None
        )
        # A local backup is not fail-closed: ``rsync`` local (no ``host:``/``user@host``)
        # is an ordinary copy, so it is not in the fold's ssh-like set and an over-cap
        # group selecting it among inert flags/paths is allowed (found in review).
        assert (
            is_denied(
                't=rsync; [ -n "$L" ] && t=cp; s=/srv/app; [ -n "$L" ] && s=./app; '
                'd=/backup; [ -n "$L" ] && d=./bak; ff=-a; [ -n "$L" ] && ff=-r; '
                'v=-v; [ -n "$L" ] && v=-q; x=--delete; [ -n "$L" ] && x=--dry-run; '
                'pp=--partial; [ -n "$L" ] && pp=--progress; $t $ff $v $x $pp $s $d'
            )
            is None
        )
        # A single-valued DOUBLING alias chain (``a1=$a2$a2; a2=$a3$a3; ...``) has
        # combos==1 but doubles the resolved word each fixpoint pass; the length cap
        # abandons it (fail-closed) instead of allocating multi-GB in the gate and
        # swallowing the MemoryError into an empty, floor-disabling frame (review).
        _dchain = (
            "; ".join("n%d=q; false || n%d=r" % (i, i) for i in range(1, 8))
            + "; "
            + "; ".join("a%d=$a%d$a%d" % (i, i + 1, i + 1) for i in range(1, 40))
            + "; a40=k; echo "
            + " ".join("$n%d" % i for i in range(1, 8))
            + " $a1"
        )
        assert is_denied(_dchain) is not None
        # A FLAG-based floor has no program: the dev-mode out-of-root confirm flag
        # assembled across an over-cap group ($p$q under opposite guards) fails
        # closed even though no candidate is a program word (found in review).
        assert (
            is_denied(
                "p=x; true && p=--confirm-out-of-install; q=y; true && q=-root; "
                "g1=1; true && g1=2; g2=1; true && g2=2; g3=1; true && g3=2; "
                "g4=1; true && g4=2; g5=1; true && g5=2; echo $p$q $g1 $g2 $g3 $g4 $g5"
            )
            is not None
        )
        assert (
            is_denied(
                "cc=gcc; cxx=g++; ar=ar; ld=ld; nm=nm; strip=strip; "
                'if [ -n "$LLVM" ]; then cc=clang; cxx=clang++; ar=llvm-ar; ld=lld; nm=llvm-nm; '
                "strip=llvm-strip; fi; ./build.sh $cc $cxx $ar $ld $nm $strip"
            )
            is None
        )
        # Six meet the cap exactly and are read in full.
        six = (
            'cc=gcc; [ -n "$USE_CLANG" ] && cc=clang; cxx=g++; [ -n "$USE_CLANG" ] && cxx=clang++; '
            'ar=ar; [ -n "$LLVM" ] && ar=llvm-ar; ld=ld; [ -n "$LLVM" ] && ld=lld; '
            'nm=nm; [ -n "$LLVM" ] && nm=llvm-nm; strip=strip; [ -n "$LLVM" ] && strip=llvm-strip; '
            "./build.sh $cc $cxx $ar $ld $nm $strip"
        )
        assert is_denied(six) is None
        for guard in ("[ -f /tmp/f ]", "true", "[ $RANDOM -gt 5 ]", '[ -n "$1" ]'):
            assert (
                is_denied(f"x=kirocrew; {guard} && x=echo; v=doctor; {guard} && v=token; $x $v")
                is not None
            ), guard
        assert (
            is_denied('x=kirocrew; [ -n "$A" ] && x=echo; v=doctor; [ -n "$A" ] || v=token; $x $v')
            is not None
        )

    def test_over_cap_fold_folds_allowed_unless_a_floor_recogniser_fires(self) -> None:
        """An over-cap group folds to ALLOWED unless a candidate token fires a floor
        recogniser; the benign-program allowlist and the "unlisted word is fail-closed"
        rule are gone (found in review).

        Removing the allowlist stopped the over-refusal a real build or deploy hit when its
        command word (``make``/``cmake``/``kubectl``) was not on the tiny benign list. An
        interpreter stays fail-closed because it mints in-process -- ``python -m kiro_crew
        token`` signs the same dashboard token as ``kirocrew token``, a cross-token shape
        the fold cannot see past the cap, so the interpreter command word denies by itself.
        Fail-closed otherwise survives only for a git publish operand (egress) and a group
        too large to enumerate (cost), each covered by its own test.
        """
        from kiro_crew.security import is_denied

        # An interpreter command word fails closed: it can mint in-process, a shape the
        # fold cannot vet past the cap -- bare and path-qualified spellings alike.
        assert (
            is_denied(
                "p=echo; false && p=python3; m=x; false && m=-m; k=y; false && k=kiro_crew; "
                "t=z; false && t=token; f1=1; false && f1=2; f2=1; false && f2=2; "
                "f3=1; false && f3=2; $p $m $k $t $f1 $f2 $f3"
            )
            is not None
        )
        assert (
            is_denied(
                "p=echo; false && p=/usr/bin/python3; a=1; false && a=2; b=1; false && b=2; "
                "c=1; false && c=2; d=1; false && d=2; e=1; false && e=2; f=1; false && f=2; "
                "$p -m kiro_crew token $a $b $c $d $e $f"
            )
            is not None
        )
        # The over-refusals the inversion removes: ordinary build/deploy/VCS command words
        # that fire no floor recogniser now fold to ALLOWED past the cap, matching base.
        assert (
            is_denied(
                'cc=gcc; [ -n "$C" ] && cc=clang; cx=g++; [ -n "$C" ] && cx=clang++; '
                'ar=ar; [ -n "$L" ] && ar=llvm-ar; ld=ld; [ -n "$L" ] && ld=lld; '
                'nm=nm; [ -n "$L" ] && nm=llvm-nm; st=strip; [ -n "$L" ] && st=llvm-strip; '
                'rl=ranlib; [ -n "$L" ] && rl=llvm-ranlib; '
                "make CC=$cc CXX=$cx AR=$ar LD=$ld NM=$nm STRIP=$st RANLIB=$rl"
            )
            is None
        )
        assert (
            is_denied(
                'cc=gcc; [ -n "$C" ] && cc=clang; cx=g++; [ -n "$C" ] && cx=clang++; '
                'bt=Release; [ -n "$D" ] && bt=Debug; j=4; [ -n "$I" ] && j=8; '
                'gen=Ninja; [ -n "$M" ] && gen=Unix; lto=ON; [ -n "$F" ] && lto=OFF; '
                'san=OFF; [ -n "$A" ] && san=ON; '
                "cmake -DCMAKE_C_COMPILER=$cc -DCMAKE_CXX_COMPILER=$cx -DCMAKE_BUILD_TYPE=$bt "
                "-DJOBS=$j -G$gen -DLTO=$lto -DSAN=$san ."
            )
            is None
        )
        assert (
            is_denied(
                'ns=default; [ -n "$P" ] && ns=prod; img=app:dev; [ -n "$P" ] && img=app:stable; '
                'cpu=100m; [ -n "$P" ] && cpu=500m; mem=128Mi; [ -n "$P" ] && mem=512Mi; '
                'rep=1; [ -n "$P" ] && rep=3; port=8080; [ -n "$P" ] && port=443; '
                'tls=off; [ -n "$P" ] && tls=on; '
                "kubectl set env deployment/app NS=$ns IMG=$img CPU=$cpu MEM=$mem "
                "REP=$rep PORT=$port TLS=$tls"
            )
            is None
        )
        # A read-only ``$vcs status`` (git or hg) past the cap carries no publish operand.
        assert (
            is_denied(
                'vcs=git; [ -n "$H" ] && vcs=hg; a=1; false && a=2; b=1; false && b=2; '
                "c=1; false && c=2; d=1; false && d=2; e=1; false && e=2; f=1; false && f=2; "
                "$vcs status $a $b $c $d $e $f"
            )
            is None
        )
        # Benign local rsync (no host:path, no remote shell) folds to allowed past the cap.
        assert (
            is_denied(
                't=rsync; [ -n "$L" ] && t=cp; s=/srv/app; [ -n "$L" ] && s=./app; '
                'd=/backup; [ -n "$L" ] && d=./bak; ff=-a; [ -n "$L" ] && ff=-r; '
                'v=-v; [ -n "$L" ] && v=-q; x=--delete; [ -n "$L" ] && x=--dry-run; '
                'pp=--partial; [ -n "$L" ] && pp=--progress; $t $ff $v $x $pp $s $d'
            )
            is None
        )
        # A WRAPPED rsync egress fails closed: rsync in operand position under a wrapper
        # (``nohup rsync host:path``) reaches a remote host just as ``nohup ssh`` does,
        # and the recogniser fires on rsync in ANY position (found in review).
        wrap = (
            "h=/tmp/o; "
            + "".join(f"{n}=1; true && {n}=2; " for n in "abcdef")
            + "true && h=localhost; "
        )
        assert is_denied(wrap + "nohup rsync --exclude=$a$b$c$d$e$f $h:/etc/shadow .") is not None
        # ...while a wrapped LOCAL rsync (no remote operand) still folds to allowed.
        assert (
            is_denied(
                "".join(f"{n}=1; true && {n}=2; " for n in "abcdefg")
                + "nohup rsync -a /src/ /dst/ $a $b $c $d $e $f $g"
            )
            is None
        )

    def test_a_subshell_scoped_append_is_read_at_the_command_run_end(self) -> None:
        """A guarded/subshell-scoped APPEND is a choice read both ways; the subshell test
        reads the command-RUN end, not the immediate next token.

        ``x=kirocrew; x+=zzz y=c | true; $x token`` puts another assignment (``y=c``)
        right after the append, so testing ``tokens[idx + 1]`` missed the ``|`` and the
        append applied in every reading -- ``$x`` read ``kirocrewzzz`` while bash ran the
        assignment-only pipe stage in a child, leaving the parent's ``$x`` as the mint
        ``kirocrew token`` (found in review). Read at ``run_end[idx]`` the ``|`` is seen
        and the un-appended reading denies, as the sibling plain-assignment branch does.
        """
        from kiro_crew.security import is_denied

        assert is_denied("x=kirocrew; x+=zzz y=c | true; $x token") is not None
        # A NON-subshell append really does change the value, so it is the pipe's
        # subshell scoping -- not the append itself -- that preserves the mint.
        assert is_denied("x=kirocrew; x+=zzz; $x token") is None

    def test_over_cap_fold_and_resolver_close_the_r57_bypasses(self) -> None:
        """The four bypasses the reviewer proved on the fail-closed-by-construction fold
        all deny, while benign rsync-local stays allowed.

        - the fold reads the FULL co-referenced group, so a use of a co-referenced but
          unguarded name (``y=$x; $y token``) is judged, not skipped;
        - rsync is benign only LOCAL: a ``host:path`` operand, or a leading
          ``RSYNC_RSH=`` remote shell, is an ssh-family egress and fails closed;
        - a name used only inside an assignment value reaches the co-reference group;
        - the guarded-reading resolver enumerates a multi-word reassigned value instead
          of the preprocessor baking the base value (``v=echo; false && v='ssh
          localhost'; RSYNC_RSH=$v rsync ...`` read ``rsync_rsh=echo`` -- found in
          review). Payloads are held in-line and verdict-checked via ``is_denied``.
        """
        from kiro_crew.security import is_denied

        # co-referenced-but-unguarded name carries the mint past the cap.
        assert (
            is_denied(
                "x=echo; false && x=a1; false && x=a2; false && x=a3; false && x=a4; "
                "false && x=a5; false && x=a6; false && x=kirocrew; y=$x; $y token"
            )
            is not None
        )
        # rsync to a remote host:path assembled past the cap is ssh-family egress.
        assert (
            is_denied(
                "h=x; false && h=a1; false && h=a2; false && h=a3; false && h=a4; "
                "false && h=a5; false && h=localhost; rsync /tmp/f $h:/tmp/"
            )
            is not None
        )
        # a guarded RSYNC_RSH remote shell, both as a leading prefix and exported, with
        # a multi-word value the resolver must carry whole rather than bake to the base.
        assert (
            is_denied("v=echo; false && v='ssh localhost'; RSYNC_RSH=$v rsync remote:/tmp/ .")
            is not None
        )
        assert (
            is_denied(
                "v=echo; false && v='ssh localhost'; export RSYNC_RSH=$v; rsync remote:/tmp/ ."
            )
            is not None
        )
        # benign rsync LOCAL (no host:path, no remote shell) stays allowed past the cap.
        assert (
            is_denied(
                't=rsync; [ -n "$L" ] && t=cp; s=/srv/app; [ -n "$L" ] && s=./app; '
                'd=/backup; [ -n "$L" ] && d=./bak; ff=-a; [ -n "$L" ] && ff=-r; '
                'v=-v; [ -n "$L" ] && v=-q; x=--delete; [ -n "$L" ] && x=--dry-run; '
                'pp=--partial; [ -n "$L" ] && pp=--progress; $t $ff $v $x $pp $s $d'
            )
            is None
        )
        # and a same-line REASSIGNED name still resolves for the floor when it is not
        # guarded (the preprocessor defers only, it does not lose the value).
        assert is_denied("v=x; v='ssh localhost'; RSYNC_RSH=$v rsync remote:/tmp/ .") is not None

    def test_line_resolver_defers_only_for_the_resolver_not_the_probe(self) -> None:
        """The ssh-to-self necessary-condition PROBE reads the FULLY substituted line, so
        an UNCONDITIONAL reassignment cannot hide the verb from the gate; the guarded
        resolver still gets the deferred form and enumerates a guarded value itself.

        Deferring a reassigned name for BOTH left ``a=x; a=s; ${a}sh localhost`` verbatim
        at the gate, which saw no ssh-family verb and returned before the resolver that
        would fold ``${a}sh`` to ``ssh`` ever ran (found in review). And a name used only
        inside an assignment value must join the command's segment, or the pairing of a
        guarded ``RSYNC_RSH`` value with the command word ``rsync`` is never read.
        Payloads in-line, verdict-checked via ``is_denied``.
        """
        from kiro_crew.security import is_denied

        # unconditional double-assignment: the gate must not defer it away.
        assert is_denied("a=x; a=s; ${a}sh localhost") is not None
        # a single same-line assignment (the round-17 case) still resolves.
        assert is_denied("a=s; ${a}sh localhost") is not None
        # a benign unconditional reassignment stays allowed (no over-refusal).
        assert is_denied("a=x; a=e; ${a}cho hi") is None
        # the guarded multi-word RSYNC_RSH value the resolver enumerates still denies.
        assert (
            is_denied("v=echo; false && v='ssh localhost'; RSYNC_RSH=$v rsync remote:/tmp/ .")
            is not None
        )
        # a name used only inside an assignment value pairs with the command word.
        assert (
            is_denied(
                "v=echo; false && v='ssh localhost'; w=1; false && w=2; "
                "RSYNC_RSH=$v rsync $w remote:/tmp/ ."
            )
            is not None
        )
        # the FULL substitution reaches the function-call binder too: an unconditional
        # double-assignment inside a bound body must not slip the resolver-less recursion.
        assert is_denied('a=x; a=s; f(){ ${a}sh "$1" id; }; f localhost') is not None
        assert is_denied('a=s; f(){ ${a}sh "$1" id; }; f localhost') is not None
        assert is_denied('f(){ echo "$1"; }; f localhost') is None

    def test_fold_ssh_recogniser_is_a_superset_of_the_floor(self) -> None:
        """PROPERTY: wherever the ssh-self FLOOR's recogniser fires on an ssh/scp/sftp
        spelling, the over-cap fold's danger recogniser fires too -- by construction,
        because both call the one ``_ssh_family_verb_of``. An exact-basename fold test
        let a glob-spelled (``/usr/bin/s?h``) or ``.exe`` binary fold to allowed while
        the floor's ``_ssh_family_verb`` glob/``.exe`` match would have denied it
        (found in review). rsync is intentionally excluded from the fold set (a local
        rsync is benign; a remote ``host:path`` operand is gated separately), so the
        superset is asserted only for the ssh-like verbs the fold claims to cover.
        """
        from kiro_crew.security.argv_floor import _ssh_family_verb
        from kiro_crew.security.shell_normalizer import _is_ssh_like_program

        spellings = []
        for verb in ("ssh", "scp", "sftp"):
            spellings += [
                verb,
                f"/usr/bin/{verb}",
                f"{verb}.exe",
                verb[0] + "?" + verb[2:],  # s?h / s?p / s?tp-ish one-char glob
                f"[{verb[0]}]{verb[1:]}",  # [s]sh
                f"/opt/x/{verb[0]}?{verb[2:]}.exe",  # path + glob + .exe
            ]
        for tok in spellings:
            floor = _ssh_family_verb(tok)
            if floor in ("ssh", "scp", "sftp"):
                assert _is_ssh_like_program(
                    tok
                ), f"fold recogniser missed a spelling the floor matches: {tok!r}"
        # end-to-end: a glob/.exe ssh binary assembled past the cap, copied and dialed
        # to this host, is denied (the F19 bypass and its .exe twin).
        from kiro_crew.security import is_denied

        fill = "b=1; true && b=2; c=1; true && c=2; d=1; true && d=2; e=1; true && e=2; f=1; true && f=2; g=1; true && g=2"
        for spell in ("/usr/bin/s?h", "ssh.exe", "/bin/s[s]h"):
            cmd = (
                f"a=x; true && a={spell}; {fill}; "
                "echo $a $b $c $d $e $f $g; cp $a /tmp/x; /tmp/x localhost"
            )
            assert is_denied(cmd) is not None, spell

    def test_the_fail_closed_reading_refuses_in_every_consuming_floor(self) -> None:
        """A group past the budget refuses whichever self-protection rows remain enabled.

        The fail-closed reading was the mint spelling, which only the mint floor
        reads: with that catalog row disabled, a ``pkill`` reading past the cap was
        replaced by a reading the self-kill floor does not match, and the command ran
        (found in review).  The reading is now one token no shell text can carry, and
        each consuming floor refuses on it for itself.
        """
        from kiro_crew import security
        from kiro_crew.security import is_denied
        from kiro_crew.security.shell_normalizer import (
            _UNREADABLE_GUARDED_READING,
            _UNREADABLE_READING_MARK,
            _is_unreadable_reading,
            _resolve_local_assignment_readings,
            normalize_shell_command,
        )

        every = [r.pattern for r in security.BUILTIN_DENIED_RULES]
        no_mint = [
            r.pattern
            for r in security.BUILTIN_DENIED_RULES
            if r.id != "credential-exfil-kirocrew-token"
        ]
        no_mint_no_kill = [
            r.pattern
            for r in security.BUILTIN_DENIED_RULES
            if r.id not in ("credential-exfil-kirocrew-token", "self-protection-kill")
        ]
        # Seven guarded choices that meet in one simple command: past the cap, so the
        # ``pkill`` reading (a guard makes it live) is never enumerated.
        seven = "".join(f"a{i}=y; true && a{i}=z; " for i in range(7))
        uses = " ".join(f"$a{i}" for i in range(7))
        kill = f"x=echo; {seven}true && x=pkill; $x kirocrew {uses}"
        readings = _resolve_local_assignment_readings(normalize_shell_command(kill))
        assert list(_UNREADABLE_GUARDED_READING) in readings
        assert _is_unreadable_reading(readings[-1])
        # The reading is not a spelling one floor happens to read: it is a word that
        # ends a C string, so no command line carries it and no floor mistakes it.
        assert "\x00" in _UNREADABLE_READING_MARK
        assert ("kirocrew", "token") != tuple(_UNREADABLE_GUARDED_READING)
        reason = is_denied(kill, denied_regexes=every)
        assert reason is not None
        # Mint row disabled: the self-kill floor refuses the same command, in its own
        # name (was allowed).
        reason = is_denied(kill, denied_regexes=no_mint)
        assert reason is not None
        assert "rule=self-protection-kill" in reason.splitlines()[-1]
        # Both rows disabled: the rows that remain still refuse; the reading reaches
        # every consumer, not the two that fired here.
        assert is_denied(kill, denied_regexes=no_mint_no_kill) is not None
        restart = f"x=echo; {seven}true && x=kirocrew; $x restart {uses}"
        assert is_denied(restart, denied_regexes=no_mint) is not None
        # Controls: a disabled row stays disabled for a command the reader CAN
        # enumerate -- the fail-closed reading is the only thing that crosses rows.
        assert is_denied("x=kirocrew; false && x=echo; $x token", denied_regexes=no_mint) is None
        assert is_denied("x=echo; true && x=pkill; $x kirocrew", denied_regexes=no_mint) is not None
        five = "".join(f"a{i}=y; true && a{i}=z; " for i in range(5))
        within = f"x=echo; {five}true && x=pkill; $x kirocrew " + " ".join(
            f"$a{i}" for i in range(5)
        )
        assert list(_UNREADABLE_GUARDED_READING) not in _resolve_local_assignment_readings(
            normalize_shell_command(within)
        )
        assert is_denied(within, denied_regexes=no_mint) is not None
        assert is_denied(within.replace("x=pkill", "x=printf"), denied_regexes=every) is None

    def test_a_variable_push_target_inside_a_carrier_is_refused_like_the_top_level_spelling(
        self,
    ) -> None:
        """A push whose destination is an expansion is refused wherever the shell runs it.

        The publish floor refuses ``b=<branch>; git push origin $b`` at top
        level: the destination cannot be determined through ``$b`` before the
        push runs, so the push is refused for a feature branch and a protected
        branch alike.  Inside a carrier the same command was ALLOWED, because
        the quoted script was shredded at its inner ``;`` in the outer frame
        and ``git push origin $b`` never reached the floor as a command line --
        a bypass of the floor, not a narrower rule.  The script is now walked
        whole, so the payload spelling meets the floor the top-level spelling
        already meets, with and without ``-u``.
        """
        from kiro_crew.security import is_denied

        for branch in ("feat/example", "main"):
            assert is_denied(f"b={branch}; git push origin $b") is not None, branch
            for cmd in (
                f"bash -c 'b={branch}; git push origin $b'",
                f"bash -c 'b={branch}; git push -u origin $b'",
            ):
                assert is_denied(cmd) is not None, cmd
        # The literal feature-branch push stays allowed in both frames.
        assert is_denied("git push origin feat/example") is None
        assert is_denied("bash -c 'true; git push origin feat/example'") is None

    def test_referenced_splits_keep_the_candidate_set_bounded(self) -> None:
        """Finding splits by reference is bounded by the references, not the ``c`` count.

        The ~3 KB alternating ``-acac…`` token (the shape that made the
        candidate set quadratic and outlived the loop watchdog) yields the
        same bounded set as before, and a payload that refers back to k
        distinct region suffixes buys NO further candidate: an earlier round
        yielded one per referenced suffix, which cost the attacker k*(k+1)/2
        characters for k full-length frames -- O(n^1.5) (found in review).
        The glued name is read by the resolver instead.
        """
        from kiro_crew.security import _shell_c_carrier_payloads

        flooded = _shell_c_carrier_payloads("-" + "ac" * 1600 + "c'git push origin main'")
        assert len(flooded) <= 70, len(flooded)
        refs = [f"${'ac' * k}" for k in range(1, 55)]
        adversary = "-c" + "ac" * 1600 + "=x; " + " ".join(refs)
        assert len(_shell_c_carrier_payloads(adversary)) <= len(flooded)
        many = " ".join("$" + "c" * k for k in range(64, 64 + 390))
        assert len(_shell_c_carrier_payloads("-" + "c" * 460 + "'echo " + many + "'")) <= 3
        one_run = _shell_c_carrier_payloads("-" + "c" * 3000 + "'git push origin main'")
        assert len(one_run) <= 3, len(one_run)
