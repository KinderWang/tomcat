/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.coyote;

import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Constants.
 *
 * @author Remy Maucherat
 */
public final class Constants {


    // -------------------------------------------------------------- Constants


    public static final String DEFAULT_CHARACTER_ENCODING="ISO-8859-1";


    public static final String LOCALE_DEFAULT = "en";


    public static final Locale DEFAULT_LOCALE = new Locale(LOCALE_DEFAULT, "");


    public static final int MAX_NOTES = 32;


    // Request states
    public static final int STAGE_NEW = 0;
    public static final int STAGE_PARSE = 1;
    public static final int STAGE_PREPARE = 2;
    public static final int STAGE_SERVICE = 3;
    public static final int STAGE_ENDINPUT = 4;
    public static final int STAGE_ENDOUTPUT = 5;
    public static final int STAGE_KEEPALIVE = 6;
    public static final int STAGE_ENDED = 7;


    /**
     * Has security been turned on?
     */
    public static final boolean IS_SECURITY_ENABLED =
        (System.getSecurityManager() != null);


    /**
     * If true, custom HTTP status messages will be used in headers.
     */
    public static final boolean USE_CUSTOM_STATUS_MSG_IN_HEADER =
        Boolean.valueOf(System.getProperty(
                "org.apache.coyote.USE_CUSTOM_STATUS_MSG_IN_HEADER",
                "false")).booleanValue(); 

    /**
     * Limit on the total length of the trailer headers in
     * a chunked HTTP request.
     */
    public static final int MAX_TRAILER_SIZE =
        Integer.parseInt(System.getProperty(
                "org.apache.coyote.MAX_TRAILER_SIZE",
                "8192"));

    /**
     * Limit on the total length of the extension data in
     * a chunked HTTP request.
     */
    public static final int MAX_EXTENSION_SIZE =
        Integer.parseInt(System.getProperty(
                "org.apache.coyote.MAX_EXTENSION_SIZE",
                "8192"));

    /**
     * Limit on the length of request body Tomcat will swallow if it is not
     * read during normal request processing. Defaults to 2MB.
     */
    public static final int MAX_SWALLOW_SIZE =
        Integer.parseInt(System.getProperty(
                "org.apache.coyote.MAX_SWALLOW_SIZE",
                "2097152"));
    
    public static final Set<String> ALLOWED_TRAILER_HEADERS;
    
    
    static {
        String commaSeparatedHeaders =
                System.getProperty("org.apache.coyote.ALLOWED_TRAILER_HEADERS");
        Set<String> headerSet = new HashSet<String>();
        if (commaSeparatedHeaders != null) {
            String[] headers = commaSeparatedHeaders.split(",");
            for (String header : headers) {
                String trimmedHeader = header.trim().toLowerCase(Locale.ENGLISH);
                if (trimmedHeader.length() > 0) {
                    headerSet.add(trimmedHeader);
                }
            }
        }
        ALLOWED_TRAILER_HEADERS = Collections.unmodifiableSet(headerSet);
    }
}
