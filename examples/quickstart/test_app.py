from app import greeting


def test_greeting() -> None:
    assert greeting("Ada") == "Hello, Ada!"
