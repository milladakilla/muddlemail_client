/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.muddlemail.MuddleClient.config;

import java.io.File;
import java.nio.charset.Charset;

/**
 * This class makes use of the "Singleton-Pattern". It represents all of the
 * system wide configurations this application will need.
 *
 * @author matt
 */
public class Config {
///////////////////////////////////////////////////////////////////////////////
// Class Variables ////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
    private static final Config instance = new Config();
    public static final String APP_NAME = "muddlemail";
    public static final String APP_VERSION = "0.0";
    public static final String APP_CHARSET = "UTF-8";
    public static final String USER_APP_DIR_NAME = "." + APP_NAME;
    public static final int SIZE_OF_ID = 50;

///////////////////////////////////////////////////////////////////////////////
// Constructors ///////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
    /**
     * Singleton protection... use getInstance().
     */
    private Config() {
    
    }

///////////////////////////////////////////////////////////////////////////////
// Methods ////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
    /**
     * This class is a singleton. You know what to do from here.
     *
     * @return instance-of-this-singleton
     */
    public static Config getInstance() {
        return instance;
    }

    /**
     * Get the name of this application.
     *
     * @return application-name
     */
    public static String getApplicationName() {
        return APP_NAME;
    }

    /**
     * Get the version number for this application.
     *
     * @return application-version-number
     */
    public static String getApplicationVersion() {
        return APP_VERSION;
    }

    /**
     * This application will be deployed as a jar. This method will get you the
     * file object that represents said jar.
     *
     * @return this-applications-jar-file
     */
    public static File getApplicationJarFile() {
        return new File(Config.class.getProtectionDomain().getCodeSource().getLocation().getPath());
    }

    /**
     * The user running this application has a home directory, no matter what OS
     * they are using. This method will tell you where that is.
     *
     * @return users-os-home-directory
     */
    public static File getUserHomeDir() {
        return new File(System.getProperty("user.home"));
    }

    /**
     * This application will need to store some data on the hard-drive. All of
     * that data will be kept in this directory.
     *
     * @return user's-application-home-director
     */
    public static File getUserApplicationDir() {
        File homeDir = getUserHomeDir();
        return new File(homeDir, USER_APP_DIR_NAME);
    }



    /**
     * This method will tell you which character encoding should be used system
     * wide. Do not use any other character encoding!!!
     *
     * @return system-wide-character-encoding
     */
    public static Charset getApplicationCharEnc() {
        return Charset.forName(APP_CHARSET);
    }

}