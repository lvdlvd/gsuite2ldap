# gsuite2ldap
serve gsuite user directory as rfc2307 compliant posixAccount, shadowAccount and posixGroup records.

According to RFC2307, the libc password, shadow and group functions should map to the following ldap queries:


        getpwnam()              (&(objectClass=posixAccount)(uid=%s))
        getpwuid()              (&(objectClass=posixAccount)(uidNumber=%d))
        getpwent()              (objectClass=posixAccount)

        getspnam()              (&(objectClass=shadowAccount)(uid=%s))
        getspent()              (objectClass=shadowAccount)

        getgrnam()              (&(objectClass=posixGroup)(cn=%s))
        getgrgid()              (&(objectClass=posixGroup)(gidNumber=%d))
        getgrent()              (objectClass=posixGroup)


The schemata for posixAccount, shadowAccount and posixGroup are: 

	posixAccount:  MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
	shadowAccount: MUST        uid
	posixGroup:    MUST ( cn $                   gidNumber )

	
all derive from top, which mandates objectClass as an attributed


	( nisSchema.1.0 NAME 'uidNumber'
          DESC 'An integer uniquely identifying a user in an administrative domain'
          EQUALITY integerMatch SYNTAX 'INTEGER' SINGLE-VALUE )

    ( nisSchema.1.1 NAME 'gidNumber'
          DESC 'An integer uniquely identifying a group in an administrative domain'
          EQUALITY integerMatch SYNTAX 'INTEGER' SINGLE-VALUE )

    ( nisSchema.1.3 NAME 'homeDirectory'
          DESC 'The absolute path to the home directory'
          EQUALITY caseExactIA5Match
          SYNTAX 'IA5String' SINGLE-VALUE )

We only serve user->uidnumber/gidnumber as derived from the gsuite user directory 'external id' type 'organisation' (employee number in the web ui dashboard)  so for lvd, employee 1000 we serve the appropriate subset of

	cn=lvd
	uid=lvd
	uidNumber=1000
	gidNumber=1000
	homeDirectory=/home/lvd

for all 3 query types.

KNOWN BUG: the TLS mechanism doesn't seem to work.  Testing with ldapsearch -ZZ, the server complains about the connection not looking like a handshake.  iirc, ldap has an in-protocol mechanism to switch to TLS on a current connection, but i don't have the time to research and implement that.




