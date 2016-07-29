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


package org.apache.catalina.startup;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.LogManager;

import org.apache.catalina.Container;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Server;
import org.apache.catalina.core.StandardServer;
import org.apache.juli.ClassLoaderLogManager;
import org.apache.tomcat.util.digester.Digester;
import org.apache.tomcat.util.digester.Rule;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;


/**
 * Startup/Shutdown shell program for Catalina.  The following command line
 * options are recognized:
 * <ul>
 * <li><b>-config {pathname}</b> - Set the pathname of the configuration file
 *     to be processed.  If a relative path is specified, it will be
 *     interpreted as relative to the directory pathname specified by the
 *     "catalina.base" system property.   [conf/server.xml]
 * <li><b>-help</b>      - Display usage information.
 * <li><b>-nonaming</b>  - Disable naming support.
 * <li><b>start</b>      - Start an instance of Catalina.
 * <li><b>stop</b>       - Stop the currently running instance of Catalina.
 * </u>
 *
 * Should do the same thing as Embedded, but using a server.xml file.
 *
 * @author Craig R. McClanahan
 * @author Remy Maucherat
 *
 */

public class Catalina extends Embedded {


    // ----------------------------------------------------- Instance Variables


    /**
     * Pathname to the server configuration file.
     */
    protected String configFile = "conf/server.xml";

    // XXX Should be moved to embedded
    /**
     * The shared extensions class loader for this server.
     */
    protected ClassLoader parentClassLoader =
        Catalina.class.getClassLoader();


    /**
     * Are we starting a new server?
     */
    protected boolean starting = false;


    /**
     * Are we stopping an existing server?
     */
    protected boolean stopping = false;


    /**
     * Use shutdown hook flag.
     */
    protected boolean useShutdownHook = true;


    /**
     * Shutdown hook.
     */
    protected Thread shutdownHook = null;


    // ------------------------------------------------------------- Properties


    public void setConfig(String file) {
        configFile = file;
    }


    public void setConfigFile(String file) {
        configFile = file;
    }


    public String getConfigFile() {
        return configFile;
    }


    public void setUseShutdownHook(boolean useShutdownHook) {
        this.useShutdownHook = useShutdownHook;
    }


    public boolean getUseShutdownHook() {
        return useShutdownHook;
    }


    /**
     * Set the shared extensions class loader.
     *
     * @param parentClassLoader The shared extensions class loader.
     */
    public void setParentClassLoader(ClassLoader parentClassLoader) {

        this.parentClassLoader = parentClassLoader;

    }


    // ----------------------------------------------------------- Main Program

    /**
     * The application main program.
     *
     * @param args Command line arguments
     */
    public static void main(String args[]) {
        (new Catalina()).process(args);
    }


    /**
     * The instance main program.
     *
     * @param args Command line arguments
     */
    public void process(String args[]) {

        setAwait(true);
        setCatalinaHome();
        setCatalinaBase();
        try {
            if (arguments(args)) {
                if (starting) {
                    load(args);
                    start();
                } else if (stopping) {
                    stopServer();
                }
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }


    // ------------------------------------------------------ Protected Methods


    /**
     * Process the specified command line arguments, and return
     * <code>true</code> if we should continue processing; otherwise
     * return <code>false</code>.
     *
     * @param args Command line arguments to process
     */
    protected boolean arguments(String args[]) {

        boolean isConfig = false;

        if (args.length < 1) {
            usage();
            return (false);
        }

        for (int i = 0; i < args.length; i++) {
            if (isConfig) {
                configFile = args[i];
                isConfig = false;
            } else if (args[i].equals("-config")) {
                isConfig = true;
            } else if (args[i].equals("-nonaming")) {
                setUseNaming( false );
            } else if (args[i].equals("-help")) {
                usage();
                return (false);
            } else if (args[i].equals("start")) {
                starting = true;
                stopping = false;
            } else if (args[i].equals("stop")) {
                starting = false;
                stopping = true;
            } else {
                usage();
                return (false);
            }
        }

        return (true);

    }


    /**
     * Return a File object representing our configuration file.
     */
    protected File configFile() {

        File file = new File(configFile);
        if (!file.isAbsolute())
            file = new File(System.getProperty("catalina.base"), configFile);
        return (file);

    }


    /**
     * Create and configure the Digester we will be using for startup.
     */
    protected Digester createStartDigester() {
        long t1=System.currentTimeMillis();
        // Initialize the digester
        Digester digester = new Digester();
        digester.setValidating(false);
        digester.setRulesValidation(true);
        HashMap<Class, List<String>> fakeAttributes = new HashMap<Class, List<String>>();
        ArrayList<String> attrs = new ArrayList<String>();
        attrs.add("className");
        fakeAttributes.put(Object.class, attrs);
        digester.setFakeAttributes(fakeAttributes);
        digester.setClassLoader(StandardServer.class.getClassLoader());

        // Configure the actions we will be using
        digester.addObjectCreate("Server",
                                 "org.apache.catalina.core.StandardServer",
                                 "className");
        digester.addSetProperties("Server");
        digester.addSetNext("Server",
                            "setServer",
                            "org.apache.catalina.Server");

        digester.addObjectCreate("Server/GlobalNamingResources",
                                 "org.apache.catalina.deploy.NamingResources");
        digester.addSetProperties("Server/GlobalNamingResources");
        digester.addSetNext("Server/GlobalNamingResources",
                            "setGlobalNamingResources",
                            "org.apache.catalina.deploy.NamingResources");

        digester.addObjectCreate("Server/Listener",
                                 null, // MUST be specified in the element
                                 "className");
        digester.addSetProperties("Server/Listener");
        digester.addSetNext("Server/Listener",
                            "addLifecycleListener",
                            "org.apache.catalina.LifecycleListener");

        digester.addObjectCreate("Server/Service",
                                 "org.apache.catalina.core.StandardService",
                                 "className");
        digester.addSetProperties("Server/Service");
        digester.addSetNext("Server/Service",
                            "addService",
                            "org.apache.catalina.Service");

        digester.addObjectCreate("Server/Service/Listener",
                                 null, // MUST be specified in the element
                                 "className");
        digester.addSetProperties("Server/Service/Listener");
        digester.addSetNext("Server/Service/Listener",
                            "addLifecycleListener",
                            "org.apache.catalina.LifecycleListener");

        //Executor
        digester.addObjectCreate("Server/Service/Executor",
                         "org.apache.catalina.core.StandardThreadExecutor",
                         "className");
        digester.addSetProperties("Server/Service/Executor");

        digester.addSetNext("Server/Service/Executor",
                            "addExecutor",
                            "org.apache.catalina.Executor");

        
        digester.addRule("Server/Service/Connector",
                         new ConnectorCreateRule());
        digester.addRule("Server/Service/Connector", 
                         new SetAllPropertiesRule(new String[]{"executor"}));
        digester.addSetNext("Server/Service/Connector",
                            "addConnector",
                            "org.apache.catalina.connector.Connector");
        
        


        digester.addObjectCreate("Server/Service/Connector/Listener",
                                 null, // MUST be specified in the element
                                 "className");
        digester.addSetProperties("Server/Service/Connector/Listener");
        digester.addSetNext("Server/Service/Connector/Listener",
                            "addLifecycleListener",
                            "org.apache.catalina.LifecycleListener");

        // Add RuleSets for nested elements
        digester.addRuleSet(new NamingRuleSet("Server/GlobalNamingResources/"));
        digester.addRuleSet(new EngineRuleSet("Server/Service/"));
        digester.addRuleSet(new HostRuleSet("Server/Service/Engine/"));
        digester.addRuleSet(new ContextRuleSet("Server/Service/Engine/Host/"));
        digester.addRuleSet(ClusterRuleSetFactory.getClusterRuleSet("Server/Service/Engine/Host/Cluster/"));
        digester.addRuleSet(new NamingRuleSet("Server/Service/Engine/Host/Context/"));

        // When the 'engine' is found, set the parentClassLoader.
        digester.addRule("Server/Service/Engine",
                         new SetParentClassLoaderRule(parentClassLoader));
        digester.addRuleSet(ClusterRuleSetFactory.getClusterRuleSet("Server/Service/Engine/Cluster/"));

        long t2=System.currentTimeMillis();
        if (log.isDebugEnabled())
            log.debug("Digester for server.xml created " + ( t2-t1 ));
        return (digester);

    }


    /**
     * Create and configure the Digester we will be using for shutdown.
     */
    protected Digester createStopDigester() {

        // Initialize the digester
        Digester digester = new Digester();

        // Configure the rules we need for shutting down
        digester.addObjectCreate("Server",
                                 "org.apache.catalina.core.StandardServer",
                                 "className");
        digester.addSetProperties("Server");
        digester.addSetNext("Server",
                            "setServer",
                            "org.apache.catalina.Server");

        return (digester);

    }


    public void stopServer() {
        stopServer(null);
    }

    public void stopServer(String[] arguments) {

        if (arguments != null) {
            arguments(arguments);
        }

        Server s = getServer();
        if( s == null ) {
            // Create and execute our Digester
            Digester digester = createStopDigester();
            digester.setClassLoader(Thread.currentThread().getContextClassLoader());
            File file = configFile();
            try {
                InputSource is =
                    new InputSource("file://" + file.getAbsolutePath());
                FileInputStream fis = new FileInputStream(file);
                is.setByteStream(fis);
                digester.push(this);
                digester.parse(is);
                fis.close();
            } catch (Exception e) {
                log.error("Catalina.stop: ", e);
                System.exit(1);
            }
        } else {
            // Server object already present. Must be running as a service
            if (s instanceof Lifecycle) {
                try {
                    ((Lifecycle) s).stop();
                } catch (LifecycleException e) {
                    log.error("Catalina.stop: ", e);
                }
                return;
            }
            // else fall down
        }

        // Stop the existing server
        s = getServer();
        try {
            if (s.getPort()>0) { 
                String hostAddress = InetAddress.getByName("localhost").getHostAddress();
                Socket socket = new Socket(hostAddress, getServer().getPort());
                OutputStream stream = socket.getOutputStream();
                String shutdown = s.getShutdown();
                for (int i = 0; i < shutdown.length(); i++)
                    stream.write(shutdown.charAt(i));
                stream.flush();
                stream.close();
                socket.close();
            } else {
                log.error(sm.getString("catalina.stopServer"));
                System.exit(1);
            }
        } catch (IOException e) {
            log.error("Catalina.stop: ", e);
            System.exit(1);
        }

    }


    /**
     * Set the <code>catalina.base</code> System property to the current
     * working directory if it has not been set.
     * @deprecated Use initDirs()
     */
    public void setCatalinaBase() {
        initDirs();
    }

    /**
     * Set the <code>catalina.home</code> System property to the current
     * working directory if it has not been set.
     * @deprecated Use initDirs()
     */
    public void setCatalinaHome() {
        initDirs();
    }

    /**
     * Start a new server instance.
     */
    public void load() {

        long t1 = System.nanoTime();

        initDirs();

        // Before digester - it may be needed

        initNaming();

        // Create and execute our Digester
        Digester digester = createStartDigester();

        InputSource inputSource = null;
        InputStream inputStream = null;
        File file = null;
        try {
            file = configFile();
            inputStream = new FileInputStream(file);
            inputSource = new InputSource("file://" + file.getAbsolutePath());
        } catch (Exception e) {
            ;
        }
        if (inputStream == null) {
            try {
                inputStream = getClass().getClassLoader()
                    .getResourceAsStream(getConfigFile());
                inputSource = new InputSource
                    (getClass().getClassLoader()
                     .getResource(getConfigFile()).toString());
            } catch (Exception e) {
                ;
            }
        }

        // This should be included in catalina.jar
        // Alternative: don't bother with xml, just create it manually.
        if( inputStream==null ) {
            try {
                inputStream = getClass().getClassLoader()
                .getResourceAsStream("server-embed.xml");
                inputSource = new InputSource
                (getClass().getClassLoader()
                        .getResource("server-embed.xml").toString());
            } catch (Exception e) {
                ;
            }
        }
        

        if ((inputStream == null) && (file != null)) {
            log.warn("Can't load server.xml from " + file.getAbsolutePath());
            if (file.exists() && !file.canRead()) {
                log.warn("Permissions incorrect, read permission is not allowed on the file.");
            }
            return;
        }

        try {
            inputSource.setByteStream(inputStream);
            digester.push(this);
            digester.parse(inputSource);
            inputStream.close();
        } catch (Exception e) {
            log.warn("Catalina.start using "
                               + getConfigFile() + ": " , e);
            return;
        }

        // Stream redirection
        initStreams();

        // Start the new server
        if (getServer() instanceof Lifecycle) {
            try {
                getServer().initialize();
            } catch (LifecycleException e) {
                if (Boolean.getBoolean("org.apache.catalina.startup.EXIT_ON_INIT_FAILURE"))
                    throw new java.lang.Error(e);
                else   
                    log.error("Catalina.start", e);
                
            }
        }

        long t2 = System.nanoTime();
        if(log.isInfoEnabled())
            log.info("Initialization processed in " + ((t2 - t1) / 1000000) + " ms");

    }


    /* 
     * Load using arguments
     */
    public void load(String args[]) {

        try {
            if (arguments(args))
                load();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }

    public void create() {

    }

    public void destroy() {

    }

    /**
     * Start a new server instance.
     */
    public void start() {

        if (getServer() == null) {
            load();
        }

        if (getServer() == null) {
            log.fatal("Cannot start server. Server instance is not configured.");
            return;
        }

        long t1 = System.nanoTime();
        
        // Start the new server
        if (getServer() instanceof Lifecycle) {
            try {
                ((Lifecycle) getServer()).start();
            } catch (LifecycleException e) {
                log.error("Catalina.start: ", e);
            }
        }

        long t2 = System.nanoTime();
        if(log.isInfoEnabled())
            log.info("Server startup in " + ((t2 - t1) / 1000000) + " ms");

        try {
            // Register shutdown hook
            if (useShutdownHook) {
                if (shutdownHook == null) {
                    shutdownHook = new CatalinaShutdownHook();
                }
                Runtime.getRuntime().addShutdownHook(shutdownHook);
                
                // If JULI is being used, disable JULI's shutdown hook since
                // shutdown hooks run in parallel and log messages may be lost
                // if JULI's hook completes before the CatalinaShutdownHook()
                LogManager logManager = LogManager.getLogManager();
                if (logManager instanceof ClassLoaderLogManager) {
                    ((ClassLoaderLogManager) logManager).setUseShutdownHook(
                            false);
                }
            }
        } catch (Throwable t) {
            // This will fail on JDK 1.2. Ignoring, as Tomcat can run
            // fine without the shutdown hook.
        }

        if (await) {
            await();
            stop();
        }

    }


    /**
     * Stop an existing server instance.
     */
    public void stop() {

        try {
            // Remove the ShutdownHook first so that server.stop() 
            // doesn't get invoked twice
            if (useShutdownHook) {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);

                // If JULI is being used, re-enable JULI's shutdown to ensure
                // log messages are not lost
                LogManager logManager = LogManager.getLogManager();
                if (logManager instanceof ClassLoaderLogManager) {
                    ((ClassLoaderLogManager) logManager).setUseShutdownHook(
                            true);
                }
            }
        } catch (Throwable t) {
            // This will fail on JDK 1.2. Ignoring, as Tomcat can run
            // fine without the shutdown hook.
        }

        // Shut down the server
        if (getServer() instanceof Lifecycle) {
            try {
                ((Lifecycle) getServer()).stop();
            } catch (LifecycleException e) {
                log.error("Catalina.stop", e);
            }
        }

    }


    /**
     * Await and shutdown.
     */
    public void await() {

        getServer().await();

    }


    /**
     * Print usage information for this application.
     */
    protected void usage() {

        System.out.println
            ("usage: java org.apache.catalina.startup.Catalina"
             + " [ -config {pathname} ]"
             + " [ -nonaming ] "
             + " { -help | start | stop }");

    }


    // --------------------------------------- CatalinaShutdownHook Inner Class

    // XXX Should be moved to embedded !
    /**
     * Shutdown hook which will perform a clean shutdown of Catalina if needed.
     */
    protected class CatalinaShutdownHook extends Thread {

        public void run() {
            try {
                if (getServer() != null) {
                    Catalina.this.stop();
                }
            } catch (Throwable ex) {
                log.error(sm.getString("catalina.shutdownHookFail"), ex);
            } finally {
                // If JULI is used, shut JULI down *after* the server shuts down
                // so log messages aren't lost
                LogManager logManager = LogManager.getLogManager();
                if (logManager instanceof ClassLoaderLogManager) {
                    ((ClassLoaderLogManager) logManager).shutdown();
                }
            }

        }

    }
    
    
    private static org.apache.juli.logging.Log log=
        org.apache.juli.logging.LogFactory.getLog( Catalina.class );

}


// ------------------------------------------------------------ Private Classes


/**
 * Rule that sets the parent class loader for the top object on the stack,
 * which must be a <code>Container</code>.
 */

final class SetParentClassLoaderRule extends Rule {

    public SetParentClassLoaderRule(ClassLoader parentClassLoader) {

        this.parentClassLoader = parentClassLoader;

    }

    ClassLoader parentClassLoader = null;

    public void begin(String namespace, String name, Attributes attributes)
        throws Exception {

        if (digester.getLogger().isDebugEnabled())
            digester.getLogger().debug("Setting parent class loader");

        Container top = (Container) digester.peek();
        top.setParentClassLoader(parentClassLoader);

    }


}
