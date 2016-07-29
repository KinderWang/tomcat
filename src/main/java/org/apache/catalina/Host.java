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

import java.util.regex.Pattern;


/**
 * A <b>Host</b> is a Container that represents a virtual host in the
 * Catalina servlet engine.  It is useful in the following types of scenarios:
 * <ul>
 * <li>You wish to use Interceptors that see every single request processed
 *     by this particular virtual host.
 * <li>You wish to run Catalina in with a standalone HTTP connector, but still
 *     want support for multiple virtual hosts.
 * </ul>
 * In general, you would not use a Host when deploying Catalina connected
 * to a web server (such as Apache), because the Connector will have
 * utilized the web server's facilities to determine which Context (or
 * perhaps even which Wrapper) should be utilized to process this request.
 * <p>
 * The parent Container attached to a Host is generally an Engine, but may
 * be some other implementation, or may be omitted if it is not necessary.
 * <p>
 * The child containers attached to a Host are generally implementations
 * of Context (representing an individual servlet context).
 *
 * @author Craig R. McClanahan
 *
 */

public interface Host extends Container {


    // ----------------------------------------------------- Manifest Constants


    /**
     * The ContainerEvent event type sent when a new alias is added
     * by <code>addAlias()</code>.
     */
    public static final String ADD_ALIAS_EVENT = "addAlias";


    /**
     * The ContainerEvent event type sent when an old alias is removed
     * by <code>removeAlias()</code>.
     */
    public static final String REMOVE_ALIAS_EVENT = "removeAlias";


    // ------------------------------------------------------------- Properties


    /**
     * Return the application root for this Host.  This can be an absolute
     * pathname, a relative pathname, or a URL.
     */
    public String getAppBase();


    /**
     * Set the application root for this Host.  This can be an absolute
     * pathname, a relative pathname, or a URL.
     *
     * @param appBase The new application root
     */
    public void setAppBase(String appBase);


    /**
     * Return the value of the auto deploy flag.  If true, it indicates that 
     * this host's child webapps should be discovred and automatically 
     * deployed dynamically.
     */
    public boolean getAutoDeploy();


    /**
     * Set the auto deploy flag value for this host.
     * 
     * @param autoDeploy The new auto deploy flag
     */
    public void setAutoDeploy(boolean autoDeploy);


    /**
     * Return the Java class name of the context configuration class
     * for new web applications.
     */
    public String getConfigClass();

    
    /**
     * Set the Java class name of the context configuration class
     * for new web applications.
     *
     * @param configClass The new context configuration class
     */
    public void setConfigClass(String configClass);

        
    /**
     * Return the value of the deploy on startup flag.  If true, it indicates 
     * that this host's child webapps should be discovred and automatically 
     * deployed.
     */
    public boolean getDeployOnStartup();


    /**
     * Set the deploy on startup flag value for this host.
     * 
     * @param deployOnStartup The new deploy on startup flag
     */
    public void setDeployOnStartup(boolean deployOnStartup);


    /**
     * Return the canonical, fully qualified, name of the virtual host
     * this Container represents.
     */
    public String getName();


    /**
     * Set the canonical, fully qualified, name of the virtual host
     * this Container represents.
     *
     * @param name Virtual host name
     *
     * @exception IllegalArgumentException if name is null
     */
    public void setName(String name);


    /**
     * Will the parsing of the web.xml file for Contexts of this Host be
     * performed by a namespace aware parser? If <code>false</code> it may still
     * be enabled per Context using
     * {@link Context#setXmlNamespaceAware(boolean)}.
     *
     * @return true if namespace awareness is enabled.
     */
    public boolean getXmlNamespaceAware();


    /**
     * Will the parsing of the web.xml file and *.tld files for Contexts of this
     * Host be performed by a validating parser? If <code>false</code> it may
     * still be enabled per Context using
     * {@link Context#setXmlValidation(boolean)}.
     *
     * @return true if validation is enabled.
     */
    public boolean getXmlValidation();


    /**
     * Controls whether the parsing of the web.xml file and *.tld files for
     * Contexts of this Host will be performed by a validating parser. If
     * <code>false</code> it may still be enabled per Context using
     * {@link Context#setXmlValidation(boolean)}.
     *
     * @param xmlValidation true to enable xml validation
     */
    public void setXmlValidation(boolean xmlValidation);


    /**
     * Controls whether the parsing of the web.xml file for Contexts of this
     * Host will be performed by a namespace aware parser. If <code>false</code>
     * it may still be enabled per Context using
     * {@link Context#setXmlNamespaceAware(boolean)}.
     *
     * @param xmlNamespaceAware true to enable namespace awareness
     */
    public void setXmlNamespaceAware(boolean xmlNamespaceAware);


    /**
     * Return the regular expression that defines the files and directories in
     * the host's {@link #getAppBase()} that will be ignored by the automatic
     * deployment process.
     */
    public String getDeployIgnore();


    /**
     * Return the compiled regular expression that defines the files and
     * directories in the host's {@link #getAppBase()} that will be ignored by
     * the automatic deployment process.
     */
    public Pattern getDeployIgnorePattern();


    /**
     * Set the regular expression that defines the files and directories in
     * the host's {@link #getAppBase()} that will be ignored by the automatic
     * deployment process.
     */
    public void setDeployIgnore(String deployIgnore);


    // --------------------------------------------------------- Public Methods


    /**
     * Add an alias name that should be mapped to this same Host.
     *
     * @param alias The alias to be added
     */
    public void addAlias(String alias);


    /**
     * Return the set of alias names for this Host.  If none are defined,
     * a zero length array is returned.
     */
    public String[] findAliases();


    /**
     * Return the Context that would be used to process the specified
     * host-relative request URI, if any; otherwise return <code>null</code>.
     *
     * @param uri Request URI to be mapped
     */
    public Context map(String uri);


    /**
     * Remove the specified alias name from the aliases for this Host.
     *
     * @param alias Alias name to be removed
     */
    public void removeAlias(String alias);


}
