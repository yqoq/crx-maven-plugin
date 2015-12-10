This plugin makes it easy to build [Chrome Apps](http://code.google.com/chrome/apps/) for the [Webstore](https://chrome.google.com/webstore) from Maven projects.  It's especially nice for developing GWT-based hosted apps, but works equally well for hand-crafted HTML and Java Script apps.  Since maven is command-line based, it allows building Chrome apps from continuous integration and build systems, using the CRX file as a natural Maven artifact.

### News ###

Version 1.1.0 is stable, and has been [released](http://crx-maven-plugin.googlecode.com/files/crx-maven-plugin-1.1.0.jar) with [notes](http://code.google.com/p/crx-maven-plugin/wiki/ReleaseNotes).

### About ###

The plugin can be configured in a pom.xml to wrap up any directory as a .crx file, but is designed to work with the maven-war-plugin to stage the target file set normally built from src/main/webapp into a war.

There are other solutions than using this crx-maven-plugin:
  * For Python: [crx-packaging](http://code.google.com/p/crx-packaging/) based on [Packing Chrome extensions in Python](http://grack.com/blog/2009/11/09/packing-chrome-extensions-in-python/)
  * For Ruby: [crxmake](http://github.com/Constellation/crxmake)


### Example Use ###
```

<!-- project artifact is a crx -->
<packaging>crx</packaging>
...

<build>
  <plugins>

    <!-- use the war plugin to stage the crx files -->
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-war-plugin</artifactId>
      <executions>
        <execution>
          <id>stage-crx</id>
          <phase>prepare-package</phase>
          <goals>
            <goal>exploded</goal>
          </goals>
        </execution>
      </executions>
    </plugin>

    <!-- the crx is created in maven's package phase -->
    <plugin>
      <groupId>com.google.code</groupId>
      <artifactId>crx-maven-plugin</artifactId>
      <version>1.1.0</version>
      <extensions>true</extensions>
      <configuration>
        <pemKey>mykey.pem</pemKey>
        <pemCert>mycert.pem</pemCert>
      </configuration>
    </plugin>

  </plugins>
</build>
...
```

### Building ###

Build the crx-maven-plugin for use locally by checking it out, and installing it.

```
svn checkout http://crx-maven-plugin.googlecode.com/svn/trunk/ crx-maven-plugin
cd crx-maven-plugin
mvn install
```

### Example Apps ###

Three Chrome Apps are built as integration tests in SVN.  These could be a starting point for your own app:
  1. maps\_app, a [Google Maps demo app](http://code.google.com/chrome/apps/docs/developers_guide.html#live)
  1. html5rocks, as an app
  1. gwt\_greet, an offline GWT AJAX app, [serverless](http://code.google.com/chrome/apps/docs/developers_guide.html#serverless)

To build them, you must enable the integration test profile:

```
# build integration tests
mvn install -P run-its
```

Keep in mind that the integration tests run their build with a clean environment. Meaning: they download a clean maven repository in the /target/ for all dependencies needed to build the sample apps.  This takes time (maybe ~30 minutes over a DSL line), so go brew some coffee while waiting.