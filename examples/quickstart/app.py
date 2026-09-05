"""A small, dependency-free project for the h00ligan guided tour."""


class GreetingStyle:
    prefix: str = "Hello"


def greeting(name: str) -> str:
    return f"Hello, {name}!"


def greet(name: str) -> str:
    return greeting(name)


def main() -> None:
    print(greet("Ada"))


def _unused() -> str:
    return "A review candidate, not permission to delete."


if __name__ == "__main__":
    main()
