# Basic Example

This is a very basic example of how to hide and use secrets

In this example we take a username and password from the command line and store them in a secret container. We class the username and password as secrets but we don't care too much about the hostname that we're connecting to.

We then try to print out the username and password (essentially for logging) but we haven't exposed the secret.

## Building 

This can be built from this directory with cmake

```
mkdir build
cd build
cmake ../
make
./c_secrecy_basic_example
```

It is also built as part of the main build process.

## Running

You need to supply a `username` and `password` at the commandline.

```
c_secrecy_basic_example alice superDuperSecret
```

You should see something like this on the command line

```
logging in user: 1��&� with password ���:�;$�x��* to localhost
logging in user: "alice" with password "superDuperSecret" to machine "localhost"
```