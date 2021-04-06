# pam_rhostfilter

Some of our users desired a way by which they could exercise some self-service control over SSH connections made to their accounts on servers.  With fixed IP addresses from which they would be connecting, a simple allow/deny by address or subnet was desirable.

Thus, a PAM module that implements an account check that validates the remote host against a user-definable configuration file was created.

##  Configuration file

By default the plugin looks for a file named `.pam_rhostfilter.conf` in the user's home directory.  The file must be:

  1. Owned by the user
  2. Have no read, write, or execute permissions to group or other users

The same mandates exist for many of the ssh configuraiton files.

### Comments

The file may contain comments, delimited by a hash (#) character.  All characters from the hash to the end o the line are discaded by the parser.

### Whitespace

Whitespace is not significant in the file.

### Rules

There are three rule types accepted.

#### Default

The `Default <disposition>` rule determines what the plugin should return if no rules match the remote host's IP address.  By default, connections are allowed — this can be made explicit:

```
#
# rhostfilter config file
#
Default Allow
```

The only other acceptable default disposition is `Deny`.

#### Deny

Access to specific hosts (by name or IP address) or entire subnets (by IP address and prefix) can be prohibited using a `Deny` rule.  Each rule consists of the `Deny` keyword followed by one or more hostnames, IP addresses, or IP address and prefix.  By default the plugin is built with IPv6 support, so both IPv4 and IPv6 addresses are accepted.

```
#
# rhostfilter config file
#
Default Allow

# Deny a hostname -- effectively all A/AAAA addresses for that name in DNS:
Deny badhost.hacker.org

# Deny two IPv4 subnets:
Deny 10.1.1.0/24 192.168.56.128/25

# Deny an IPv6 address (google.com):
Deny 2607:f8b0:4006:81a::200e
```

#### Allow

When the default is set to `Deny`, exceptions take the form of an `Allow` rule.  Each rule consists of the `Allow` keyword followed by one or more hostnames, IP addresses, or IP address and prefix (the same format as `Deny` rules).

### Advanced configurations

The `Default` rule can be used multiple times but only its final occurrence is significant.  The default disposition is `Allow` as an attept to protect users from accidentially locking themselves out of their account.  **Be very careful when authoring a configuration with a default disposition of deny; be sure to test prior to closing your connection to the remote system!**  (Testing configuration files is covered in a later section of this document.)

Since the rules are processed in sequence and processing ends on the first match, rule ordering can be important.  With a default disposition of `Allow`, any `Allow` rule functions as an early exit point.  Protecting a specific host/subnet from a later `Deny` rule that would match it, for example:

```
#
# rhostfilter config file
#
Default Allow

# Deny a hostname -- effectively all A/AAAA addresses for that name in DNS:
Deny badhost.hacker.org

# A couple exceptions to the Deny rule that follows:
Allow 10.1.1.5 10.1.1.200 192.168.56.192

# Deny two IPv4 subnets:
Deny 10.1.1.0/24 192.168.56.128/25

# Deny an IPv6 address (google.com):
Deny 2607:f8b0:4006:81a::200e
```

## Building the software

The build process uses CMake 3.12 or better and your system's default development toolchain.

```
$ ls -1
CMakeLists.txt
README.md
pam_rhostfilter.c
pam_rhostfilter.conf

$ mkdir build ; cd build

$ cmake -DCMAKE_BUILD_TYPE=Release ..

$ make
```

If successful, The `build` directory should contain the PAM module (`pam_rhostfilter.so`) and the configuration checker (`pam_rhostfilter_check`).  The module can be installed in your systems PAM modules directory (e.g. `/usr/lib64/security` on CentOS 7).  Feel free to copy the checker program to `/usr/local/bin`, for example:  it should be available to all users who plan to author configuration files.

The `PAM_BYHOST_IPV4_ONLY` binary build option disables the resolution and parsing of textual addresses to IPv6 addresses.  By default the module and checker utility include IPv6 support.

## Checking a configuration

The configuration checker uses a small number of options and arguments:

```
$ ./pam_rhostfilter_check --help
usage:

    ./pam_rhostfilter_check {options> <hostname|ip-address> {<hostname|ip-address> ..}

  options:

    --help/-h                      show this information
    --conf/-c <filename>           use this configuration file instead
                                   of the default (/home/1001/.pam_rhostfilter.conf)
    --syntax/-s                    check file syntax only, no hostnames
                                   or addresses necessary

```

In its simplest mode, a syntax check of a configuration file is effected.  Consider the example file in the advanced configuration section above:

```
$ ./pam_rhostfilter_check --conf=pam_rhostfilter.conf --syntax
ERROR:  configuration file not acceptable: pam_rhostfilter.conf (errno = 1)
```

The file in question is owned by me, but has mode 0644; no group- or other-user permission are allowed on the file:

```
$ chmod 0600 pam_rhostfilter.conf

$ ./pam_rhostfilter_check --conf=pam_rhostfilter.conf --syntax
[INFO] Setting default disposition to Allow on line 4
[INFO] Found Deny rule on line 7:
[INFO] Found Allow rule on line 10:
[INFO] Found Deny rule on line 13:
[INFO] Found Deny rule on line 16:
```

No errors were found in the configuration file.  If I misspell one of the keywords, for example:

```
$ ./pam_rhostfilter_check --conf=pam_rhostfilter.conf --syntax
[INFO] Setting default disposition to Allow on line 4
[INFO] Found Deny rule on line 7:
[INFO] Found Allow rule on line 10:
[INFO] Found Deny rule on line 13:
[ERR ] Invalid rule on line 16: Denied 2607:f8b0:4006:81a::200e
```

The checker can also be used to test the set of rules against one of more hostnames, IP addresses, or IP addresses with prefix:

```
$ ./pam_rhostfilter_check --conf=pam_rhostfilter.conf google.com
[INFO] Setting default disposition to Allow on line 4
[INFO] Found Deny rule on line 7:
[FAIL]     badhost.hacker.org (unable to resolve)
[INFO] Found Allow rule on line 10:
[ OK ]     10.1.1.5
        prefix length = -1
[INFO]        0   172.217.9.238
[INFO]            0   10.1.1.5
[INFO]        1   2607:f8b0:4006:081a:0000:0000:0000:200e
[ OK ]     10.1.1.200
        prefix length = -1
[INFO]        0   172.217.9.238
[INFO]            0   10.1.1.200
[INFO]        1   2607:f8b0:4006:081a:0000:0000:0000:200e
[ OK ]     192.168.56.192
        prefix length = -1
[INFO]        0   172.217.9.238
[INFO]            0   192.168.56.192
[INFO]        1   2607:f8b0:4006:081a:0000:0000:0000:200e
[INFO] Found Deny rule on line 13:
[ OK ]     10.1.1.0
        prefix length = 24
[INFO]            IPv6 mask: 0xffffff00000000000000000000000000
[INFO]            IPv4 mask: 0xffffff00
[INFO]        0   172.217.9.0
[INFO]            0   10.1.1.0
[INFO]        1   2607:f800:0000:0000:0000:0000:0000:0000
[ OK ]     192.168.56.128
        prefix length = 25
[INFO]            IPv6 mask: 0xffffff80000000000000000000000000
[INFO]            IPv4 mask: 0xffffff80
[INFO]        0   172.217.9.128
[INFO]            0   192.168.56.128
[INFO]        1   2607:f880:0000:0000:0000:0000:0000:0000
[INFO] Found Deny rule on line 16:
[ OK ]     2607:f8b0:4006:81a::200e
        prefix length = -1
[INFO]        0   172.217.9.238
[INFO]        1   2607:f8b0:4006:081a:0000:0000:0000:200e
[INFO]            0   2607:f8b0:4006:081a:0000:0000:0000:200e
[INFO]                IPv6 MATCH!
```

Note that the entire list of rules will be checked:  the utility does not exit on the first match, but the first match is easily visible in the output.

## PAM configuration

An example `/etc/pam.d/sshd` configuration might look like:

```
   :
account    required     pam_nologin.so
account    required     pam_rhostfilter.so debug noconf=deny noresolve=deny
account    include      password-auth
   :
```

This module only implements a concrete *account* function; attempting to use pam_rhostfilter.so in the *auth*, *session*, or *password* modes will yield an error.

If `debug` is included in the argument list, additional information is logged to the syslog debug facility.

The `noconf=deny` option enforces the implementation of a `~/.pam_rhostfilter.conf` configuration file for all connections.  Any user lacking a file or with the file not properly owned and permissioned will be denied all access.  This option is likely only useful on systems with few users all of very high capability (e.g. system administrators).

The `noresolve=deny` option indicates the disposition returned for any remote host that is provided to the module as a hostname and that hostname cannot be resolved to any IP address.  This is very unlikely to happen, since if PAM cannot resolve the IP to a name it will probably pass the IP address to this plugin.

