
An application bases much of its security on knowing who a user of the system is.
Authentication is the process of verifying identity, proving that a subject **is**
who *it* claims to be.

Factors of Authentication
-------------------------
Authentication methodologies involve three factors:
    - something the user **knows**
    - something the user **has**
    - something the user **is**

Authentication methods that depend on more than one factor, known as multi-factor
authentication (MFA) methods, are considered stronger fraud deterrents than
single-factor methods as they are more difficult to compromise.  A bank ATM
transaction involves MFA because it requires something the user **has** -- a bank card --
*and* it requires something the user **knows** -- a PIN code.

The use of a username/password to login is considered single-factor
authentication because it only involves something the user *knows*.

Yosai is designed to accomodate multi-factor authentication methods.   Be that
as it may, no concrete MFA implementation is provided within the core library
because the MFA chosen is discretionary and largely subject to change among
projects.  Instead, the Yosai community is encouraged to share extensions to enable MFA. 

However, although no multi-factor solution is provided, a single-factor, password-based 
authentication is provided in yosai.core because it remains the most widely used form 
of authentication.  


Password-based Authentication
-----------------------------
When a developer wishes to authenticate a user using password-based methods,
the first step requires instantiation of an ``AuthenticationToken`` object 
recognizable by Yosai.  The UsernamePasswordToken implementation suffices for
this purpose.  UsernamePasswordToken is a consolidation of a user account's 
identifying attributes (username) and credentials (password):

.. code-block:: python
    authc_token = UsernamePasswordToken(username='thedude',
                                        credentials='letsgobowling')

Using the Subject API, you c



Yosai uses the Passlib library for cryptographic hashing.

The default hashing scheme chosen for Yosai is *bcrypt_sha256*. As per Passlib
documentation [1], the *bcrypt_sha256* algorithm works as follows:

    - First, the password is encoded to UTF-8 if not already encoded.
    - Then, the UTF-8 encoded password is run through SHA2-256, generating a 32-byte digest
    - The 32-byte digest is encoded using base64, resulting in a 44-byte result
      (including the trailing padding '='):
          For the example "password", the output from this stage would be:
            "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=".

    - Finally, the base64 string is passed on to the underlying bcrypt algorithm
      as the new password to be hashed.

Example
-------
In this example, we "log in" a Subject, performing password-based authentication
that raises an AuthenticationException if authentication were to fail:

.. code-block:: python

    from yosai.core import SecurityUtils, AuthenticationToken

    authc_token = UsernamePasswordToken(username='thedude',
                                        credentials='letsgobowling')

    subject = SecurityUtils.get_subject()
    subject.login(authc_token)



[1] Passlib - bcrypt_sha256 documentation https://pythonhosted.org/passlib/lib/passlib.hash.bcrypt_sha256.html#algorithm
