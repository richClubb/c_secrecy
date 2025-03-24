# C Secrecy

A library to replicate the functionality of the secrecy crate in Rust in C++

## Objectives

The main things the secrecy crate in rust gives us are:
* ability to hide the value of the variable and only be exposed explicitly (by calling `expose_value()`)
* zero out the memory location after the variable has been deleted

This gives the ability to audit the secrets a bit easier as you can always see where `expose_value()` is called.

As C does not have the ability to hide member variables we encrypt the data when it's stored so that it is 'harder' to access, and the use of expose_value allows us to extract the data to get a better audit of the values stored in the secrets.

## To-Do

* CI/CD pipeline
* Properly arrange make files
* Integration tests?
  * What might they be?
* Investigate virtual classes for extensibility
* Cross compile for different arch / OS
  * Currently only tested in Linux but I want this to be used in windows
* Set up release process

* Is there a better way to store the keys so that we can use this like a better encrypted storage container.
* Is there a better way to expose they keys?
* ways to do this with debugging allowing values?