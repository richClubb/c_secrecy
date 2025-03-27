# Basic Example

This is a very basic example of how to use the C secrecy library.

In this example we take a username and password from the command line and store them in a secret container. We class the username and password as secrets but we don't care too much about the hostname that we're connecting to.

We then try to print out the username and password (essentially for logging) but we haven't exposed the secret.

The main thing is that the secrets are created and the only way to expose them is via the `expose_secret()` method. This will be easier to audit and understand the scope of the exposure when using that variable.

## Building 

This can be built from this directory with cmake

```
mkdir build
cd build
cmake ../
make
```

This also is built as part of the main build process as well.

If you build this in this directory you will need to add the library path to `LD_LIBRARY_PATH` or use it in the invocation. If you're using the devcontainer then this will work.

```
LD_LIBRARY_PATH=/workspaces/c_secrecy/build/lib ./c_secrecy_example [a] [b]
```

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