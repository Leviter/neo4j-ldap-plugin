Configuration of the LDAP plugin extension
==========================================

It is required that you have sessions enabled for the web server since the extension depends on it.

Create the jar file by using a `mvn clean package`
Copy the jar file from the target directory into the Neo4J installation's 'plugins' directory
Download the 'commons-codec-1.9.jar' and store it with the plugin in the 'plugins' directory

Add the following line to the neo4j-server.properties:

```
org.neo4j.server.rest.security_rules=org.theblackproject.neo4j.plugin.authentication.LDAPAuthenticationRule
```

1. Make sure the NEO4J_HOME environment variable is set
2. In the folder NEO4J_HOME a folder named 'conf' should be present
3. Inside the 'conf' folder, create a file named 'ldap.properties'

Properties
----------

```
basic.authentication.realm=WallyWorld

ldap.authentication.context.factory=com.sun.jndi.ldap.LdapCtxFactory

ldap.authentication.uri.path=/*

ldap.provider.url=ldap://ad.mydomain.com:389
ldap.security.authentication=simple
ldap.security.principal=username
ldap.security.credentials=password

ldap.search.user.base=<base DN>
ldap.search.user.check.memberof=true
ldap.search.user.memberof.group=<group CN ... only used if ldap.search.user.check.memberof is set to true>
```