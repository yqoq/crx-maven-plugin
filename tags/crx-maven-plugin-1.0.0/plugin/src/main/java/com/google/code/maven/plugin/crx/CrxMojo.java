package com.google.code.maven.plugin.crx;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.codehaus.plexus.util.StringUtils;

/**
 * Creates a Chrome CRX Webapp Archive.
 * 
 * Generally Chrome Webapps are an extended form of Chrome Extensions. They have
 * a <a
 * href="http://code.google.com/chrome/extensions/manifest.html">manifest</a>,
 * and other files, required to run the app. Chrome Webapps must be signed to be
 * used in the <a href="">Chrome Web Store</a>. See the Installable Web Apps <a
 * href="http://code.google.com/chrome/apps/docs/developers_guide.html"
 * >developer guide</a> for more info.
 * 
 * The Chrome browser executable can be used to generate CRX files, and at the
 * time of writing this, is the reference for CRX generation. Chrome can be
 * called from the <a
 * href="http://code.google.com/chrome/extensions/packaging.html#H2-2">command
 * line</a> like so:
 * 
 * <pre>
 * <code>
 * /Applications/Google Chrome.app/Contents/MacOS/Google Chrome \
 *   --enable-apps \
 *   --pack-extension=my_app \
 *   --pack-extension-key=my_app.pem \
 *   --no-message-box
 *   </code>
 * </pre>
 * 
 * 
 * 
 * @goal crx
 * @phase package
 * @requiresDependencyResolution runtime
 */
public class CrxMojo extends AbstractMojo {
	/**
	 * The Project.
	 * 
	 * @parameter expression="${project}"
	 * @required
	 * @readonly
	 */
	private MavenProject project;

	/**
	 * The Project Helper.
	 * 
	 * @component
	 */
	private MavenProjectHelper helper;

	/**
	 * Directory where the crx file should be written to.
	 * 
	 * @parameter expression="${project.build.directory}"
	 * @required
	 */
	private File targetDir;

	/**
	 * The directory where the webapp is built. If this mojo is used in
	 * conjunction with the maven-war-plugin, the default values for both
	 * plugins should be sufficient. This will let the maven-war-plugin stage
	 * all files required for the CRX into the webappDirectory, while the
	 * crx-maven-plugin actually builds the file from that staging directory.
	 * 
	 * @parameter 
	 *            expression="${project.build.directory}/${project.build.finalName}"
	 * @required
	 */
	private File webappDirectory;

	/**
	 * Name of the generated CRX (without the ".crx" extension).
	 * 
	 * @parameter expression="${project.build.finalName}"
	 * @required
	 */
	private String targetFile;

	/**
	 * Classifier to add to the artifact generated.
	 * 
	 * @parameter
	 */
	private String classifier;

	/**
	 * The comma separated list of tokens to include when copying content of the
	 * warSourceDirectory. Default is '**'.
	 * 
	 * @parameter alias="includes"
	 */
	private String webappIncludes = "**";

	/**
	 * The comma separated list of tokens to exclude when copying content of the
	 * warSourceDirectory.
	 * 
	 * @parameter alias="excludes"
	 */
	private String webappExcludes;

	/**
	 * PEM format private key in pk8 format.
	 * 
	 * Typically this is generated by Chrome the first time you create a CRX
	 * file, but it can also be generated using openssl. Generate the
	 * keypair_pk8.pem file for use as the <code>pemKey</code> like so:
	 * 
	 * <pre>
	 * <code>
	 * openssl genrsa -out keypair.pem 1024
	 * openssl pkcs8 -topk8 -in keypair.pem -inform pem -out keypair_pk8.pem -outform pem -nocrypt
	 * </code>
	 * </pre>
	 * 
	 * Then use the "keypair_pk8.pem" file as the pemKey.
	 * 
	 * @parameter expression="${crx.pemKey}"
	 * @required
	 */
	private File pemKey;

	/**
	 * PEM format public key.
	 * 
	 * The public key needs to be extracted from the private key file to be
	 * bundled into the CRX file by the plugin. This file is required by the
	 * plugin, as I couldn't figure out how to extract the public key from the
	 * private key file using JCE (hints are welcome). Generate using the
	 * pemCert from the pemKey, like so:
	 * 
	 * <pre>
	 * <code>
	 * # to extract the public key from an RSA private key, try: 
	 * openssl rsa -in keypair_pk8.pem -pubout > cert.pem
	 * </code>
	 * </pre>
	 * 
	 * Then use the "public.pem" file as the pemCert.
	 * 
	 * @parameter expression="${crx.pemCert}"
	 * @required
	 */
	private File pemCert;

	/**
	 * Executes the task. In this case, packages the crx.
	 * 
	 * @throws MojoExecutionException
	 *             on archiver error.
	 */
	public final void execute() throws MojoExecutionException {

		getLog().debug("====== BEGIN MAVEN-CRX-PLUGIN ======");
		getLog().debug("targetDir  [" + targetDir + "]");
		getLog().debug("targetFile [" + targetFile + ".crx]");
		getLog().debug("webappDir [" + webappDirectory.toString() + "]");

		try {
			// the CRX file to generate
			File crx = new File(targetDir, targetFile + ".crx");
			getLog().debug("targetFile [" + crx + "]");

			// create the crx file
			if (getLog().isDebugEnabled()) {
				getLog().debug(
						"Loading PEM files: key=" + pemKey + " cert=" + pemCert);
			}
			CrxUtil util = new CrxUtil(pemKey, pemCert);

			getLog().info("Packaging Chrome CRX");

			crx = util.buildCrx(webappDirectory, crx.getAbsolutePath());

			if (classifier == null) {
				project.getArtifact().setFile(crx);
			} else {
				getLog().info("Attaching CRX for " + classifier);
				helper.attachArtifact(project, "crx", classifier, crx);
			}

		} catch (Exception e) {
			throw new MojoExecutionException("Error packaging CRX", e);
		}

		getLog().debug("====== END MAVEN-CRX-PLUGIN ======");
	}

	/**
	 * Returns a string array of the excludes to be used when copying the
	 * content of the war source directory.
	 * 
	 * @return an array of tokens to exclude
	 */
	protected String[] getExcludes() {
		List<String> excludeList = new ArrayList<String>();
		if (StringUtils.isNotEmpty(webappExcludes)) {
			excludeList.addAll(Arrays.asList(StringUtils.split(webappExcludes,
					",")));
		}

		return excludeList.toArray(new String[] {});
	}

	/**
	 * Returns a string array of the includes to be used when assembling/copying
	 * the war.
	 * 
	 * @return an array of tokens to include
	 */
	protected String[] getIncludes() {
		ArrayList<String> includes = new ArrayList<String>();

		includes.addAll(Arrays.asList(StringUtils.split(
				StringUtils.defaultString(webappIncludes), ",")));

		return includes.toArray(new String[] {});
	}
}
