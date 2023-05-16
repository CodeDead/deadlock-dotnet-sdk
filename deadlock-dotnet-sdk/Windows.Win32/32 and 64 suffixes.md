The "32" and "64" suffixes indicate the bitness of the pointers (`UIntPtr32<T>`, `UIntPtr64<T>`¹) and the bitness of the pointers' owner process.


¹ The generic Type `T` indicates the pointer type is a pointer to an object of type `T`. This is intended to mimic conventional pointer types' syntax. `UIntPtr32<int>` is intended to be equivalent to a 32-bit process's `int*`.
