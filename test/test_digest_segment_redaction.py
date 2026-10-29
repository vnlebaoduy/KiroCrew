"""A hex digest in a URL path survives the bare-secret pass; a key beside one does not.

An object-store or artifact URL is one run of base64-alphabet characters, and its
window straddling a short mixed-case segment and a sha256 clears every per-window
gate. The digest ceiling (``_HEX_DIGEST_SEGMENT_RE``, ``_DIGEST_PIECE_MIN``) declines
that window, only inside a URL path (``_URL_PATH_RE``), without freeing a key placed
before, after or glued to a digest.
"""

from __future__ import annotations

import random
import string

import pytest

from kiro_crew.security import redact_credentials
from kiro_crew.security import redaction as _redaction

# The canonical AWS documentation example secret key, never a live credential.
KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
MD5 = SHA256[:32]
SHA1 = "cc504736836c7c1905f86f8cd4e0c9b46b37347c"
TAG = "[REDACTED: credential]"
# A key whose last `/`-segment holds twelve hex digits, one below the floor.
SLASH_HEX12_KEY = "wJalrXUtnFEMIQK7MDENGQbPxRf/3f9c0a7b1d4e"
# A key whose first 28 characters are hex, as in a reviewer's repro.
HEX_START_KEY = "3f9c0a7b1d4e7c2b9a0f5d3e8c1b/RWG27KFEB2V"
# A key whose last segment is itself 32 hex digits, as in a reviewer's repro.
SEGMENT_KEY = "Rq7Zt4W/9e3f1a6c0b8d2e7f4a5c9b1d3e6f0a8c"
# The same key with thirteen hex digits in that segment, at the floor.
SLASH_HEX13_KEY = "wJalrXUtnFEMIQK7MDENGQbPxR/3f9c0a7b1d4e8"


def _segments(seed: int, count: int) -> list[str]:
    rng = random.Random(seed)
    alphabet = string.ascii_letters + string.digits
    return ["".join(rng.choice(alphabet) for _ in range(rng.randint(2, 12))) for _ in range(count)]


@pytest.mark.parametrize(
    "template",
    [
        "https://s3.amazonaws.com/bucket/{seg}/{digest}/output.zip",
        "https://ex.com/getObject/{seg}/{digest}",
        "https://artifacts.example/Releases/{seg}/{digest}/pkg.tar.gz",
    ],
)
@pytest.mark.parametrize("digest", [SHA256, SHA1, MD5])
def test_a_digest_path_segment_survives(template: str, digest: str) -> None:
    for seg in _segments(11, 300):
        url = template.format(seg=seg, digest=digest)
        assert redact_credentials(url) == (url, []), url


def test_the_fixture_shape_fires_without_the_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    # Proves the test above exercises the ceiling: with it disabled, some link fires.
    monkeypatch.setattr(_redaction, "_DIGEST_PIECE_MIN", _redaction._SECRET_KEY_LEN + 1)
    fired = [
        seg
        for seg in _segments(11, 300)
        if redact_credentials(f"https://ex.com/getObject/{seg}/{SHA256}")[1]
    ]
    assert fired


@pytest.mark.parametrize(
    "text",
    [
        f"https://ex.com/getObject/Kx9/{SHA256}/{KEY}",
        f"https://ex.com/{KEY}/{SHA256}",
        f"{KEY}{SHA256}",
        f"{SHA256}{KEY}",
        f"{SLASH_HEX12_KEY}{SHA1}",
        f"{SLASH_HEX12_KEY}{SHA1[:28]}/README.md",
    ],
)
def test_a_key_beside_or_glued_to_a_digest_is_still_redacted(text: str) -> None:
    result, warnings = redact_credentials(text)
    assert KEY not in result and SLASH_HEX12_KEY not in result
    assert TAG in result
    assert warnings


@pytest.mark.parametrize(
    "text",
    [
        f"{SLASH_HEX13_KEY}{SHA256}",
        f"key: {SLASH_HEX13_KEY}{SHA1}/README.md",
        f"see https://ex.com/a then {SLASH_HEX13_KEY}{SHA256}",
    ],
)
def test_the_ceiling_holds_only_inside_a_url_path(text: str) -> None:
    # Outside a URL path the digest gives no reason to decline a window, so a
    # key whose last segment runs on into the digest's hex is still found.
    result, warnings = redact_credentials(text)
    assert SLASH_HEX13_KEY not in result
    assert warnings


def test_a_segment_after_the_digest_is_a_pinned_residual() -> None:
    # A window starting inside the digest is never declined: a key that starts
    # with hex and is glued after short hex makes the same window, so such a
    # link is still redacted for some segments. Pinned so a change is seen.
    fired = [
        seg
        for seg in _segments(11, 300)
        if redact_credentials(f"https://ex.com/bucket/{SHA256}/{seg}/file")[1]
    ]
    assert fired


@pytest.mark.parametrize(
    "template",
    [
        "https://ex.com/{}",
        "https://ex.com/{}/x",
        "https://ex.com/a/{}?q=1",
        "https://ex.com/Z{}",
        "https://ex.com/bucket/" + SHA256 + "/Z{}",
    ],
)
def test_a_key_that_is_a_whole_digest_shaped_segment_is_redacted(template: str) -> None:
    # The key's own last segment is 32 hex digits and its window ends there,
    # so the digest ceiling must not decline it, glued after anything or not.
    assert _redaction._looks_like_secret_key(SEGMENT_KEY)
    result, warnings = redact_credentials(template.format(SEGMENT_KEY))
    assert SEGMENT_KEY not in result
    assert warnings


@pytest.mark.parametrize(
    "text",
    [
        f"https://ex.com/b/cc504736836c{HEX_START_KEY}/x",
        f"https://github.com/o/r/blob/cc504736836c{HEX_START_KEY}",
    ],
)
def test_a_key_that_starts_with_hex_glued_after_hex_is_redacted(text: str) -> None:
    # The key brings most of a 40-digit hex segment; its own window starts
    # inside that segment and must still be judged.
    result, warnings = redact_credentials(text)
    assert HEX_START_KEY not in result
    assert warnings


def test_the_url_path_scheme_is_left_guarded_and_bounded() -> None:
    # The URL-path scan runs over the whole text once a run holds a digest. A
    # scheme that may start at any offset, or run on without bound, re-reads a
    # long run of scheme characters at every offset; this pins both guards.
    assert _redaction._URL_PATH_RE.match("a://h/p", 0)
    assert not _redaction._URL_PATH_RE.match("xa://h/p", 1)
    assert _redaction._URL_PATH_RE.match("a" * 32 + "://h/p")
    assert not _redaction._URL_PATH_RE.search("a" * 33 + "://h/p")


def test_seeded_keys_around_a_digest_are_redacted() -> None:
    """Every key-shaped window a key brings is still classified at its own offset."""
    rng = random.Random(5)
    alphabet = string.ascii_letters + string.digits + "+/"
    checked = 0
    while checked < 300:
        key = "".join(rng.choice(alphabet) for _ in range(40))
        if not _redaction._looks_like_secret_key(key):
            continue
        if key.count("/") > _redaction._SECRET_MAX_SLASHES:
            continue
        for text in (
            f"{key}/{SHA256}",
            f"{SHA256}/{key}",
            f"{key}{SHA256}",
            f"{SHA256}{key}",
            f"https://ex.com/getObject/Kx9/{SHA256}/{key}",
        ):
            assert key not in redact_credentials(text)[0], text
        checked += 1


def test_a_window_reads_only_the_digest_it_can_cross() -> None:
    """One bisect: a window crosses only the first digest starting after it."""
    starts = [i * 70 for i in range(1, 4097)]
    assert _redaction._crosses_into_a_digest(70 * 2048 - 20, starts)
    assert not _redaction._crosses_into_a_digest(70 * 2048 - 28, starts)
