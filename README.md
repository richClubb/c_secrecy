# NOTE

This has been combined with the C++ version to make a single C compatible library (libsecrecy)(https://github.com/richClubb/libsecrecy)

This branch is not going to be actively maintained

# C Secrecy

A library to replicate the functionality of the secrecy crate in Rust in C++

## Objectives

The main things the secrecy crate in rust gives us are:
* ability to hide the value of the variable and only be exposed explicitly (by calling `expose_value()`)
* zero out the memory location after the variable has been deleted

This gives the ability to audit the secrets a bit easier as you can always see where `expose_value()` is called.

As C does not have the ability to hide member variables we encrypt the data when it's stored so that it is 'harder' to access, and the use of expose_value allows us to extract the data to get a better audit of the values stored in the secrets.

The encryption is not designed to be "secure" but more just help to obfuscate the value. In some ways it does provide a measure of security as if a secret does leak then the value should be sufficiently well encrypted that it would be impossible for a user to use it.

## Building

```
mkdir build
cd build
cmake ../
make
```

This should generate the library (`lib/libc_secrecy.so`) and also generate the test `build/tests/unit/c_secrecy_unit_tests`.

Currently only compiles for x86 on linux.

## Debugging

There should be a working debug target for the unit tests.

## To-Do

* CI/CD pipeline
* Properly arrange make files
* Integration tests?
  * What might they be?
* Cross compile for different arch / OS
  * Currently only tested in Linux but I want this to be used in windows
  * aarch64
  * embedded
* Set up release process

* Is there a better way to store the keys so that we can use this like a better encrypted storage container.
* Is there a better way to expose they keys?
* ways to do this with debugging allowing values?

* investigate if there is a way to make the encryption more secure. I'm not sure if there is a nice way to do key management.

## Example Program

```


```