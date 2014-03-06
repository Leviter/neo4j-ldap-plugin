package org.theblackproject.neo4j.plugin.authentication;

import lombok.extern.slf4j.Slf4j;
import org.theblackproject.neo4j.plugin.authentication.configuration.Configuration;
import org.apache.commons.codec.binary.Base64;
import org.neo4j.server.rest.security.SecurityFilter;
import org.neo4j.server.rest.security.SecurityRule;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Hashtable;

@Slf4j
public class LDAPAuthenticationRule implements SecurityRule {

	private static final String SESSION_AUTHENTICATION_KEY = "user_authenticated";

	private static final String HEADER_AUTHORIZATION = "authorization";

	private static final String MEMBER_OF = "memberOf";
	private static final String DISTINGUISHED_NAME = "distinguishedName";

	public static final String SEARCH_BY_SAM_ACCOUNT_NAME = "(sAMAccountName=%s)";

	private DirContext ctx = null;

	@Override
	public boolean isAuthorized(HttpServletRequest httpServletRequest) {
		boolean userIsAuthenticated = false;

		HttpSession session = httpServletRequest.getSession();
		Boolean isAuthenticated = (Boolean) session.getAttribute(SESSION_AUTHENTICATION_KEY);

		if ((isAuthenticated == null) || (!isAuthenticated)) {
			String[] credentials = getAuthorization(httpServletRequest);

			if (credentials != null) {
				try {
					Hashtable<String, String> env = new Hashtable<String, String>();
					env.put(Context.INITIAL_CONTEXT_FACTORY, Configuration.getContextFactory());
					env.put(Context.PROVIDER_URL, Configuration.getProviderUrl());
					env.put(Context.REFERRAL, "follow");

					env.put(Context.SECURITY_AUTHENTICATION, Configuration.getAuthentication());
					env.put(Context.SECURITY_PRINCIPAL, Configuration.getPrincipal());
					env.put(Context.SECURITY_CREDENTIALS, Configuration.getCredentials());

					ctx = new InitialDirContext(env);

					String filter = String.format(SEARCH_BY_SAM_ACCOUNT_NAME, credentials[0]);
					SearchControls constraints = new SearchControls();
					constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
					constraints.setReturningAttributes(new String[]{MEMBER_OF, DISTINGUISHED_NAME});

					NamingEnumeration results = ctx.search(Configuration.getUserBase(), filter, constraints);

					// Filtered on unique name, so one result should be expected here!
					if (results != null && results.hasMore()) {

						SearchResult result = (SearchResult) results.next();

						// Get the entry's attributes
						Attributes attributes = result.getAttributes();
						String distinguishedName = (String) attributes.get(DISTINGUISHED_NAME).get();

						boolean isMemberOfGroup = (Configuration.isCheckUserGroup() && userIsMemberOfGroup(attributes.get(MEMBER_OF))) || (!Configuration.isCheckUserGroup());

						if (isMemberOfGroup) {
							log.debug("Authenticating user");

							env.put(Context.SECURITY_PRINCIPAL, distinguishedName);
							env.put(Context.SECURITY_CREDENTIALS, credentials[1]);

							new InitialDirContext(env);

							userIsAuthenticated = true;
						}
					}
				} catch (NamingException e) {
					log.error("Failed connecting/authenticating to LDAP", e);
				} finally {
					if (ctx != null) {
						try {
							ctx.close();
						} catch (NamingException ignored) {
						}
					}
				}
			}
		} else {
			userIsAuthenticated = true;
		}

		session.setAttribute(SESSION_AUTHENTICATION_KEY, userIsAuthenticated);

		return userIsAuthenticated;
	}

	@Override
	public String forUriPath() {
		return Configuration.getUriPath();
	}

	@Override
	public String wwwAuthenticateHeader() {
		return SecurityFilter.basicAuthenticationResponse(Configuration.getRealm());
	}

	private String[] getAuthorization(HttpServletRequest request) {
		String[] decoded = null;
		String authorization = request.getHeader(HEADER_AUTHORIZATION);
		if (authorization != null) {
			// There is a space between "Basic" and the Base 64 encoded string.
			authorization = authorization.substring("Basic ".length());
			decoded = new String(Base64.decodeBase64(authorization)).split(":");
		}
		return decoded;
	}

	private boolean userIsMemberOfGroup(Attribute memberOfAttribute) throws NamingException {
		log.debug("Checking if user is member of group");

		NamingEnumeration groups = memberOfAttribute.getAll();

		while (groups.hasMore()) {
			String group = (String) groups.next();

			if (group.equals(Configuration.getUserMemberOfGroup())) {
				log.debug("User is a member!");
				return true;
			}
		}

		return false;
	}
}
