package org.theblackproject.neo4j.plugin.authentication.configuration;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

@Slf4j
public class Configuration {

	private static final Properties properties = loadProperties();

	private static final String CONFIGURATION_FILE_NAME = "ldap.properties";
	private static final String CONFIGURATION_FOLDER = "conf";


	@Getter(AccessLevel.PUBLIC)
	private static String contextFactory = getStringProperty("ldap.authentication.context.factory");

	@Getter(AccessLevel.PUBLIC)
	private static String uriPath = getStringProperty("ldap.authentication.uri.path");

	@Getter(AccessLevel.PUBLIC)
	private static String realm = getStringProperty("basic.authentication.realm");

	@Getter(AccessLevel.PUBLIC)
	private static String providerUrl = getStringProperty("ldap.provider.url");
	@Getter(AccessLevel.PUBLIC)
	private static String authentication = getStringProperty("ldap.security.authentication");
	@Getter(AccessLevel.PUBLIC)
	private static String principal = getStringProperty("ldap.security.principal");
	@Getter(AccessLevel.PUBLIC)
	private static String credentials = getStringProperty("ldap.security.credentials");

	@Getter(AccessLevel.PUBLIC)
	private static String userBase = getStringProperty("ldap.search.user.base");
	@Getter(AccessLevel.PUBLIC)
	private static boolean checkUserGroup = getBooleanProperty("ldap.search.user.check.memberof");
	@Getter(AccessLevel.PUBLIC)
	private static String userMemberOfGroup = getStringProperty("ldap.search.user.memberof.group");


	private static String getStringProperty(String name) {
		return getStringProperty(name, "");
	}

	private static boolean getBooleanProperty(String name) {
		return getBooleanProperty(name, false);
	}

	private static String getStringProperty(String name, String defaultValue) {
		String value = properties.getProperty(name);

		return (value == null) ? defaultValue : value;
	}

	private static boolean getBooleanProperty(String name, boolean defaultValue) {
		String value = properties.getProperty(name);

		return (value == null) ? defaultValue : Boolean.parseBoolean(value);
	}

	private static Properties loadProperties() {
		final String neo4jHome = getNeo4jHome();

		if (neo4jHome == null) {
			throw new RuntimeException("NEO4J_HOME not set! Unable to load configuration file.");
		}

		String configurationFile = neo4jHome + File.separator + CONFIGURATION_FOLDER + File.separator + CONFIGURATION_FILE_NAME;
		log.info("Loading configuration file : " + configurationFile);

		final Properties properties = new Properties();
		InputStream inputStream = null;
		try {
			File propertiesFile = new File(configurationFile);
			inputStream = new FileInputStream(propertiesFile);
			properties.load(inputStream);
		} catch (IOException e) {
			log.error("Could not load properties for LDAP authentication extension", e);
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException ignored) {
				}
			}
		}

		return properties;
	}

	private static String getNeo4jHome() {
		String neo4jHome = System.getProperty("NEO4J_HOME");

		if (neo4jHome == null) {
			neo4jHome = System.getProperty("neo4j.home");
		}

		return neo4jHome;
	}
}
