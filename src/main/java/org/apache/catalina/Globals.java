/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.apache.catalina;


/**
 * Global constants that are applicable to multiple packages within Catalina.
 *
 * @author Craig R. McClanahan
 *
 */

public final class Globals {

    /**
     * The servlet context attribute under which we store the alternate
     * deployment descriptor for this web application
     */
    public static final String ALT_DD_ATTR =
        "org.apache.catalina.deploy.alt_dd";

    /**
     * The request attribute under which we store the array of X509Certificate
     * objects representing the certificate chain presented by our client,
     * if any.
     */
    public static final String CERTIFICATES_ATTR =
        "javax.servlet.request.X509Certificate";

    /**
     * The request attribute under which we store the name of the cipher suite
     * being used on an SSL connection (as an object of type
     * java.lang.String).
     */
    public static final String CIPHER_SUITE_ATTR =
        "javax.servlet.request.cipher_suite";


    /**
     * The servlet context attribute under which we store the class loader
     * used for loading servlets (as an object of type java.lang.ClassLoader).
     */
    public static final String CLASS_LOADER_ATTR =
        "org.apache.catalina.classloader";

    /**
     * Request dispatcher state.
     */
    public static final String DISPATCHER_TYPE_ATTR =
        "org.apache.catalina.core.DISPATCHER_TYPE";

    /**
     * Request dispatcher path.
     */
    public static final String DISPATCHER_REQUEST_PATH_ATTR =
        "org.apache.catalina.core.DISPATCHER_REQUEST_PATH";

    /**
     * The JNDI directory context which is associated with the context. This
     * context can be used to manipulate static files.
     */
    public static final String RESOURCES_ATTR =
        "org.apache.catalina.resources";


    /**
     * The servlet context attribute under which we store the class path
     * for our application class loader (as an object of type String),
     * delimited with the appropriate path delimiter for this platform.
     */
    public static final String CLASS_PATH_ATTR =
        "org.apache.catalina.jsp_classpath";


    /**
     * The request attribute under which we forward a Java exception
     * (as an object of type Throwable) to an error page.
     */
    public static final String EXCEPTION_ATTR =
        "javax.servlet.error.exception";


    /**
     * The request attribute under which we forward the request URI
     * (as an object of type String) of the page on which an error occurred.
     */
    public static final String EXCEPTION_PAGE_ATTR =
        "javax.servlet.error.request_uri";


    /**
     * The request attribute under which we forward a Java exception type
     * (as an object of type Class) to an error page.
     */
    public static final String EXCEPTION_TYPE_ATTR =
        "javax.servlet.error.exception_type";


    /**
     * The request attribute under which we forward an HTTP status message
     * (as an object of type STring) to an error page.
     */
    public static final String ERROR_MESSAGE_ATTR =
        "javax.servlet.error.message";


    /**
     * The request attribute under which the Invoker servlet will store
     * the invoking servlet path, if it was used to execute a servlet
     * indirectly instead of through a servlet mapping.
     */
    public static final String INVOKED_ATTR =
        "org.apache.catalina.INVOKED";


    /**
     * The request attribute under which we expose the value of the
     * <code>&lt;jsp-file&gt;</code> value associated with this servlet,
     * if any.
     */
    public static final String JSP_FILE_ATTR =
        "org.apache.catalina.jsp_file";


    /**
     * The request attribute under which we store the key size being used for
     * this SSL connection (as an object of type java.lang.Integer).
     */
    public static final String KEY_SIZE_ATTR =
        "javax.servlet.request.key_size";

    /**
     * The request attribute under which we store the session id being used
     * for this SSL connection (as an object of type java.lang.String).
     */
    public static final String SSL_SESSION_ID_ATTR =
        "javax.servlet.request.ssl_session";


    /**
     * The servlet context attribute under which the managed bean Registry
     * will be stored for privileged contexts (if enabled).
     */
    public static final String MBEAN_REGISTRY_ATTR =
        "org.apache.catalina.Registry";


    /**
     * The servlet context attribute under which the MBeanServer will be stored
     * for privileged contexts (if enabled).
     */
    public static final String MBEAN_SERVER_ATTR =
        "org.apache.catalina.MBeanServer";


    /**
     * The request attribute under which we store the servlet name on a
     * named dispatcher request.
     */
    public static final String NAMED_DISPATCHER_ATTR =
        "org.apache.catalina.NAMED";


    /**
     * The request attribute under which the request URI of the included
     * servlet is stored on an included dispatcher request.
     */
    public static final String INCLUDE_REQUEST_URI_ATTR =
        "javax.servlet.include.request_uri";


    /**
     * The request attribute under which the context path of the included
     * servlet is stored on an included dispatcher request.
     */
    public static final String INCLUDE_CONTEXT_PATH_ATTR =
        "javax.servlet.include.context_path";


    /**
     * The request attribute under which the path info of the included
     * servlet is stored on an included dispatcher request.
     */
    public static final String INCLUDE_PATH_INFO_ATTR =
        "javax.servlet.include.path_info";


    /**
     * The request attribute under which the servlet path of the included
     * servlet is stored on an included dispatcher request.
     */
    public static final String INCLUDE_SERVLET_PATH_ATTR =
        "javax.servlet.include.servlet_path";


    /**
     * The request attribute under which the query string of the included
     * servlet is stored on an included dispatcher request.
     */
    public static final String INCLUDE_QUERY_STRING_ATTR =
        "javax.servlet.include.query_string";


    /**
     * The request attribute under which the original request URI is stored
     * on an forwarded dispatcher request.
     */
    public static final String FORWARD_REQUEST_URI_ATTR =
        "javax.servlet.forward.request_uri";


    /**
     * The request attribute under which the original context path is stored
     * on an forwarded dispatcher request.
     */
    public static final String FORWARD_CONTEXT_PATH_ATTR =
        "javax.servlet.forward.context_path";


    /**
     * The request attribute under which the original path info is stored
     * on an forwarded dispatcher request.
     */
    public static final String FORWARD_PATH_INFO_ATTR =
        "javax.servlet.forward.path_info";


    /**
     * The request attribute under which the original servlet path is stored
     * on an forwarded dispatcher request.
     */
    public static final String FORWARD_SERVLET_PATH_ATTR =
        "javax.servlet.forward.servlet_path";


    /**
     * The request attribute under which the original query string is stored
     * on an forwarded dispatcher request.
     */
    public static final String FORWARD_QUERY_STRING_ATTR =
        "javax.servlet.forward.query_string";


    /**
     * The request attribute under which we forward a servlet name to
     * an error page.
     */
    public static final String SERVLET_NAME_ATTR =
        "javax.servlet.error.servlet_name";


    /**
     * The name of the cookie used to pass the session identifier back
     * and forth with the client.
     */
    public static final String SESSION_COOKIE_NAME =
        System.getProperty("org.apache.catalina.SESSION_COOKIE_NAME",
                "JSESSIONID");


    /**
     * The name of the path parameter used to pass the session identifier
     * back and forth with the client.
     */
    public static final String SESSION_PARAMETER_NAME =
        System.getProperty("org.apache.catalina.SESSION_PARAMETER_NAME",
                "jsessionid");


    /**
     * The servlet context attribute under which we store a flag used
     * to mark this request as having been processed by the SSIServlet.
     * We do this because of the pathInfo mangling happening when using
     * the CGIServlet in conjunction with the SSI servlet. (value stored
     * as an object of type String)
     */
     public static final String SSI_FLAG_ATTR =
         "org.apache.catalina.ssi.SSIServlet";


    /**
     * The request attribute under which we forward an HTTP status code
     * (as an object of type Integer) to an error page.
     */
    public static final String STATUS_CODE_ATTR =
        "javax.servlet.error.status_code";


    /**
     * The subject under which the AccessControlContext is running.
     */
    public static final String SUBJECT_ATTR =
        "javax.security.auth.subject";


    /**
     * The servlet context attribute under which we record the set of
     * welcome files (as an object of type String[]) for this application.
     */
    public static final String WELCOME_FILES_ATTR =
        "org.apache.catalina.WELCOME_FILES";


    /**
     * The servlet context attribute under which we store a temporary
     * working directory (as an object of type File) for use by servlets
     * within this web application.
     */
    public static final String WORK_DIR_ATTR =
        "javax.servlet.context.tempdir";


    /**
     * The request attribute that is set to <code>Boolean.TRUE</code> if some request
     * parameters have been ignored during request parameters parsing. It can
     * happen, for example, if there is a limit on the total count of parseable
     * parameters, or if parameter cannot be decoded, or any other error
     * happened during parameter parsing.
     */
    public static final String PARAMETER_PARSE_FAILED_ATTR =
        "org.apache.catalina.parameter_parse_failed";


    /**
     * The reason that the parameter parsing failed.
     */
    public static final String PARAMETER_PARSE_FAILED_REASON_ATTR =
            "org.apache.catalina.parameter_parse_failed_reason";


    /**
     * The master flag which controls strict servlet specification
     * compliance.
     */
    public static final boolean STRICT_SERVLET_COMPLIANCE =
        Boolean.valueOf(System.getProperty("org.apache.catalina.STRICT_SERVLET_COMPLIANCE", "false")).booleanValue();


    /**
     * Has security been turned on?
     */
    public static final boolean IS_SECURITY_ENABLED =
        (System.getSecurityManager() != null);


    /**
     * Name of the system property containing
     * the Tomcat product installation path
     */
    public static final String CATALINA_HOME_PROP = "catalina.home";


    /**
     * Name of the system property containing
     * the Tomcat instance installation path
     */
    public static final String CATALINA_BASE_PROP = "catalina.base";


    /**
     * Name of the ServletContext init-param that determines if the JSP engine
     * should validate *.tld files when parsing them.
     * <p>
     * This must be kept in sync with org.apache.jasper.Constants
     */
    public static final String JASPER_XML_VALIDATION_TLD_INIT_PARAM =
            "org.apache.jasper.XML_VALIDATE_TLD";


    /**
     * Name of the ServletContext init-param that determines if the JSP engine
     * should validate web.xml files when parsing them.
     * <p>
     * This must be kept in sync with org.apache.jasper.Constants
     */
    public static final String JASPER_XML_VALIDATION_INIT_PARAM =
            "org.apache.jasper.XML_VALIDATE";


    /**
     * Name of the ServletContext init-param that determines if the JSP engine
     * will block external entities from being used in *.tld, *.jspx, *.tagx and
     * tagplugin.xml files.
     * <p>
     * This must be kept in sync with org.apache.jasper.Constants
     */
    public static final String JASPER_XML_BLOCK_EXTERNAL_INIT_PARAM =
            "org.apache.jasper.XML_BLOCK_EXTERNAL";
}
