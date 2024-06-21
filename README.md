# Wildboar SASL Server

This is not even an alpha release yet. It is not even working yet. This is a
work in progress.

---

## Purpose

SASL is a flexible authentication protocol that uses a string to identify an
authentication mechanism, such as `PLAIN`, and zero or more binary messages that
adhere to a format defined for that mechanism, which contain authentication
assertions from a user trying to proof his identity. These assertions are
generally checked against some authoritative database of users, such as an
LDAP / X.500 directory, an OpenID provider, a Kerberos server, or the Unix
`/etc/passwd` or `/etc/shadow` databases. Continuing with the `PLAIN` mechanism
as an example, the assertion for this mechanism would contain a username and
password, with no encryption or hashing of any kind, and the asserted username
and password might be submitted to an 

Though authentication decisions typically take the form of a simple "pass" or
"fail," information about a user usually can be obtained from one of these
identity stores once they have authenticated. For instance, an LDAP directory
can return a user's display name, email address, and phone number to the
application, if the user authenticates.

The versatility of SASL makes it desirable for defining protocols that require
authentication, hence its widespread adoption. However, integration with
several identity providers, and the logic to handle many different
authentication mechanisms, requires a lot of code, which will often have to run
with heightened privileges or in a sensitive context. For instance, if a SQL
database that stores usernames and passwords is used for authentication, an
application that checks if a username and password are valid according to this
database will necessarily need (at least) read-only access to the username and
password data. For that matter, supporting MySQL, Postgres, SQL Server, SQLite,
LDAP, Kerberos, OpenID, Unix passwords, Active Directory, etc. will require a
lot of code, which itself is a maintenance and security liability, and will
produce huge binaries that take a long time to build. This also means that
multiple applications can use the exact same authentication sources without
requiring their own separate configuration.

These considerations make it worthwhile to extract authentication into a
separate "microservice." Instead of having the code for dozens of identity
providers built into your application, and instead of allowing your application
to directly interface with sensitive stores of user information, applications
can be written with a single client library that interfaces with this SASL
server. This SASL server can also run with the minimum necessary privileges
with only the permissions required to perform authentication.

The protocol provided by this SASL server is extremely simple. It has two
functions:

- `GetAvailableMechanisms`, which lists the SASL mechanisms available.
- `Authenticate`, which is the remote procedure for actually authenticating,
  possibly returning information about the user if they have authenticated
  successfully.

These functions are defined as gRPC interfaces, meaning that clients can be
generated trivially for any widely-used programming language.

## Thoughts Scratchpad

Alternative idea:

https://doc.dovecot.org/developer_manual/design/auth_protocol/#dovecot-auth-protocol

Some applications may require more application-specific data per user,
rather than just "pass or fail." For instance, some email systems need to know
the UID, GID, home directory, and chroot for a user. It would be a waste if
LDAP was configured as an identity store, and then relying applications still
had to query the LDAP server for user properties. This is what Dovecot's
authentication protocol does.

However, this complicates things, because not all identity stores (such as
Kerberos) can return any user information at all. So there needs to be some
concept of potential subsequent steps after authentication succeeds to obtain
more information about the user.

## Terminology

- User - the person or service authenticating
- Client - the application that is verifying the authenticity of the user using
  this SASL server protocol.
- Server - the SASL server.

## To Do

- [ ] Identity Store
  - [x] Memory (Might be renamed to `UsersFile`)
  - [ ] X.500 Directory
  - [ ] LDAP Server
  - [ ] OpenID
  - [ ] Kerberos
  - [ ] Unix Shadow
  - [ ] Rhai Script
  - [ ] SQL Database
- [ ] Authentication Mechanisms
  - [x] `PLAIN`
  - [x] `OTP` (Apparently, this has NO relation to the HOTP or TOTP widely in use now...)
  - [x] `ANONYMOUS` (It takes an arbitrary "trace string." Unclear if it can fail.)
  - [ ] `OAUTHBEARER`
    - [ ] Token introspection https://www.rfc-editor.org/rfc/rfc7662
  - [ ] `EXTERNAL`
    - Takes UTF-8 authorization identity
  - [ ] `SCRAM-*`
  - [ ] `SAML20`
    - This is going to require an HTTP endpoint where responses can be received.
    - Exposing a public HTTP service diminishes the security of this...
  - [ ] `OAUTH10A`
  - [ ] `OPENID20`
    - I just learned today that this is not the same as OpenID Connect...
  - [ ] `KERBEROS5`
  - [ ] `SECURID`
  - [ ] `EAP-AES128`
  - [ ] `EAP-AES128-PLUS`
  - [ ] `GS2-KRB5`
  - [ ] `GS2-KRB5-PLUS`
- [ ] Not-yet-defined authentication mechanisms
  - [ ] `OPENID-CONNECT`
  - [ ] `HOTP`
  - [ ] `TOTP`
- [ ] Credential change interface?
- [ ] Web Interface?

## Data Model

- There is no such thing as workflows. Users can only pick a single auth
  mechanism.
- Users cannot pick the identity store, but the client can.
- Identity stores: databases, files, services, or other sources of user
  information.
