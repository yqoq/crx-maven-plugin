package com.google.code.maven.plugin.crx;

import java.io.File;
import java.io.FilenameFilter;
import java.util.Collection;
import java.util.Vector;

public class FileUtil {
	/**
	 * Find files in the given directory, and return them as an array.
	 * 
	 * @param directory
	 * @param filter
	 * @param recurse
	 * @return an array of Files that pass the FilenameFilter
	 */
	public static File[] listFilesAsArray(File directory,
			FilenameFilter filter, boolean recurse) {
		Collection<File> files = listFiles(directory, filter, recurse);

		File[] arr = new File[files.size()];
		return files.toArray(arr);
	}

	/**
	 * Find files in the given directory and subdirectories that are accepted by
	 * the given FilenameFilter.
	 * 
	 * @param directory
	 *            search start directory
	 * @param filter
	 *            an implementation of FilenameFilter
	 * @param recurse
	 *            true if subdirectories should be recursively searched.
	 * @see FilenameFilter
	 * @return a collection of Files that pass the FilenameFilter
	 */
	public static Collection<File> listFiles(File directory,
			FilenameFilter filter, boolean recurse) {
		Vector<File> files = new Vector<File>();

		// Get files / directories in the directory
		File[] entries = directory.listFiles();

		// Go over entries
		for (File entry : entries) {
			// If there is no filter or the filter accepts the
			// file / directory, add it to the list
			if (filter == null || filter.accept(directory, entry.getName())) {
				files.add(entry);
			}

			// If the file is a directory and the recurse flag
			// is set, recurse into the directory
			if (recurse && entry.isDirectory()) {
				files.addAll(listFiles(entry, filter, recurse));
			}
		}

		// Return collection of files
		return files;
	}
}
