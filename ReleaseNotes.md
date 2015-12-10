# 1.1.0 #

Added includes/excludes capability, so things like WEB-INF won't be packaged.

Added maven-ant-plugin based creation of .ZIP file, to the GWT integration-test, for easy publishing to the Chrome App Store.


# 1.0.0 #

Allows for creating basic CRX files using Maven.

Supports signing of the CRX file using key pairs.

See the included integration-test projects for examples of:
  * Basic Chrome App (shortcut-style app)
  * HTML5 Packaged App (_html5rocks_, as an app)
  * GWT Packaged App (once installed, no network is needed)