from typing import List, Callable, Literal, Hashable, get_origin, get_args, TypeVar, Annotated
from collections.abc import Callable as ABCCallable
from functools import wraps


T = TypeVar('T')


class RuntimeTypeConstraints:
    def __init__(self, *constraints: Callable[[T], bool]):
        self.constraints = list(constraints)

    def validate(self, instance):
        try:
            return all(constraint(instance) for constraint in self.constraints)
        except:
            return False

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({[f'cons{i}' for i in range(len(self.constraints))]})"


def assert_strict(func):
    type_hints = func.__annotations__
    if not type_hints:
        raise TypeError(f"Function '{func.__name__}' must have type annotations for all arguments and return value in strict mode.")

    for param in func.__code__.co_varnames[:func.__code__.co_argcount]:
        if param not in type_hints:
            raise TypeError(f"Argument '{param}' in function '{func.__name__}' must have a type annotation in strict mode.")

    if 'return' not in type_hints:
        raise TypeError(f"Function '{func.__name__}' must have a return type annotation in strict mode.")


def check_callable(value, expected_type):
    """Check if a callable matches the expected Callable type."""
    if not isinstance(value, (Callable, ABCCallable)):
        return False

    expected_args = get_args(expected_type)
    if len(expected_args) != 2:
        raise ValueError(f"Expected Callable with a single argument and return type, got: {expected_args}")

    arg_type, return_type = expected_args
    try:
        if hasattr(value, '__annotations__'):
            annotations = value.__annotations__
            param_types = list(annotations.values())[:-1]
            result_type = annotations.get('return', None)

            if len(param_types) != 1:
                return False

            if isinstance(arg_type, type) and isinstance(param_types[0], type):
                if not issubclass(arg_type, param_types[0]):
                    return False

            if return_type is not None and result_type is not None:
                if isinstance(return_type, type) and isinstance(result_type, type):
                    if not issubclass(result_type, return_type):
                        return False
        return True
    except Exception as e:
        raise ValueError(f"Error validating callable: {e}")


def check_type(value, expected_type):
    origin = get_origin(expected_type)
    args = get_args(expected_type)

    if origin is Annotated:
        base_type, *metadata = args
        if not check_type(value, base_type):
            return False
        for meta in metadata:
            if isinstance(meta, RuntimeTypeConstraints) and not meta.validate(value):
                return False
        return True

    if origin is Literal:
        return value in args

    if origin is not None:
        if not isinstance(value, origin):
            return False
        if args:
            if origin is list:
                return all(check_type(v, args[0]) for v in value)
            if origin is Callable or origin is ABCCallable:
                return check_callable(value, expected_type)
            assert False, f"Unsupported origin: {origin}."

    return isinstance(value, expected_type)


def debug_argument(expected_type, arg) -> str:
    origin = get_origin(expected_type)
    args = get_args(expected_type)
    if origin is Literal:
        return f"'{arg}', type: '{type(arg)}'"
    if origin is Annotated:
        _, *metadata = args
        constraints = [cons for meta in metadata if isinstance(meta, RuntimeTypeConstraints) for cons in meta.constraints]
        violated = []
        for i, cons in enumerate(constraints):
            try:
                add = not cons(arg)
            except:
                add = True
            if add:
                violated.append(f"cons{i}")
        return f"'{arg}', type: '{type(arg)}', violated constraints: '{violated}'"
    return f"type: '{type(arg)}'"


def type_check_decorator(strict: bool = True) -> Callable:
    def decorator(func: Callable) -> Callable:
        if strict:
            assert_strict(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            type_hints = func.__annotations__

            for arg, (name, expected_type) in zip(args, type_hints.items()):
                if name == "return":
                    continue
                if not check_type(arg, expected_type):
                    raise TypeError(f"Argument '{name}' must be of type '{expected_type}', got {debug_argument(expected_type, arg)}.")

            for name, arg in kwargs.items():
                if name in type_hints and not check_type(arg, type_hints[name]):
                    raise TypeError(f"Argument '{name}' must be of type '{type_hints[name]}', got {debug_argument(expected_type, arg)}.")

            result = func(
                *[type_check_decorator(strict=strict)(arg) if callable(arg) else arg for arg in args],
                **{k: type_check_decorator(strict=strict)(arg) if callable(arg) else arg for k, arg in kwargs.items()}
            )  # TODO: wrap recursively, [lambda x: True, ...]

            return_type = type_hints.get('return', None)
            if return_type and not check_type(result, return_type):
                raise TypeError(f"Return value must be of type '{return_type}', got {debug_argument(expected_type, arg)}.")

            return result

        return wrapper

    return decorator


@type_check_decorator(strict=True)
def f(
    lst: Annotated[List[list[str]], RuntimeTypeConstraints(
        lambda lst: all("l" in s for sublist in lst for s in sublist),
        lambda lst: len(lst) == 2,
        lambda lst: set(lst[0]) <= {"hello", "world"},
    )],
    call: Callable[[str], int],
    lit: Literal["a", "b"],
    integer: Annotated[int, RuntimeTypeConstraints(
        lambda integer: 0 <= integer <= 100,
    )],
) -> Hashable:
    if lit == "a":
        return tuple(call(item) for sublist in lst for item in sublist)
    if lit == "b":
        return frozenset(call(item) for sublist in lst for item in sublist)
    raise ValueError("Invalid value for 'a'. Must be 'a' or 'b'.")


if __name__ == "__main__":
    def transform(value: str) -> int:
        return len(value)
    nested_list = [["hello", "world"], ["hello"]]
    result = f(nested_list, transform, "a", 0)
    print(result)
