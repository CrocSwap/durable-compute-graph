"""Registered DCG v2 kernels, mirrored from crates/dcg-kernels for tracing and host execution."""

from __future__ import annotations

from dcg.tracing import KernelSpec, Value, call

ADD_I32 = KernelSpec(1, "add_i32", 2)
IDENTITY_I32 = KernelSpec(2, "identity_i32", 1)
REGISTRY = {k.code: k for k in (ADD_I32, IDENTITY_I32)}


def add_i32(a: Value, b: Value) -> Value:
    return call(ADD_I32, a, b)


def identity_i32(a: Value) -> Value:
    return call(IDENTITY_I32, a)


def host(kernel: KernelSpec, args: list[int]) -> int:
    if kernel is ADD_I32:
        out = args[0] + args[1]
        if not -(2**31) <= out < 2**31:
            raise OverflowError("signed 32-bit overflow")
        return out
    if kernel is IDENTITY_I32:
        return args[0]
    raise KeyError(kernel.name)
