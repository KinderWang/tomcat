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


package org.apache.catalina.session;


import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.management.MBeanRegistration;
import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Globals;
import org.apache.catalina.Manager;
import org.apache.catalina.Session;
import org.apache.catalina.core.ContainerBase;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.core.StandardHost;
import org.apache.catalina.util.StringManager;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.modeler.Registry;


/**
 * Minimal implementation of the <b>Manager</b> interface that supports
 * no session persistence or distributable capabilities.  This class may
 * be subclassed to create more sophisticated Manager implementations.
 *
 * @author Craig R. McClanahan
 *
 */
public abstract class ManagerBase implements Manager, MBeanRegistration {

    protected Log log = LogFactory.getLog(ManagerBase.class);

    // ----------------------------------------------------- Instance Variables

    private static final String devRandomSourceDefault;
    static {
        // - Use the default value only if it is a Unix-like system
        // - Check that it exists 
        File f = new File("/dev/urandom");
        if (f.isAbsolute() && f.exists()) {
            devRandomSourceDefault = f.getPath();
        } else {
            devRandomSourceDefault = null;
        }
    }

    protected DataInputStream randomIS=null;
    protected String devRandomSource = devRandomSourceDefault;

    /**
     * The default message digest algorithm to use if we cannot use
     * the requested one.
     */
    protected static final String DEFAULT_ALGORITHM = "MD5";


    /**
     * The message digest algorithm to be used when generating session
     * identifiers.  This must be an algorithm supported by the
     * <code>java.security.MessageDigest</code> class on your platform.
     */
    protected String algorithm = DEFAULT_ALGORITHM;


    /**
     * The Container with which this Manager is associated.
     */
    protected Container container;


    /**
     * Return the MessageDigest implementation to be used when
     * creating session identifiers.
     */
    protected MessageDigest digest = null;


    /**
     * The distributable flag for Sessions created by this Manager.  If this
     * flag is set to <code>true</code>, any user attributes added to a
     * session controlled by this Manager must be Serializable.
     *
     * @deprecated Ignored. {@link Context#getDistributable()} always takes
     *             precedence. Will be removed in Tomcat 9.0.x.
     */
    @Deprecated
    protected boolean distributable;


    /**
     * A String initialization parameter used to increase the entropy of
     * the initialization of our random number generator.
     */
    protected String entropy = null;


    /**
     * The descriptive information string for this implementation.
     */
    private static final String info = "ManagerBase/1.0";


    /**
     * The default maximum inactive interval for Sessions created by
     * this Manager.
     *
     * @deprecated Ignored. {@link Context#getSessionTimeout()} always takes
     *             precedence. Will be removed in Tomcat 9.0.x.
     */
    @Deprecated
    protected int maxInactiveInterval = 30 * 60;


    /**
     * The session id length of Sessions created by this Manager.
     */
    protected int sessionIdLength = 16;


    /**
     * The descriptive name of this Manager implementation (for logging).
     */
    protected static String name = "ManagerBase";


    /**
     * A random number generator to use when generating session identifiers.
     */
    protected Random random = null;


    /**
     * The Java class name of the random number generator class to be used
     * when generating session identifiers.
     */
    protected String randomClass = "java.security.SecureRandom";


    /**
     * The longest time (in seconds) that an expired session had been alive.
     */
    protected int sessionMaxAliveTime;


    /**
     * Average time (in seconds) that expired sessions had been alive.
     */
    protected int sessionAverageAliveTime;


    protected static final int TIMING_STATS_CACHE_SIZE = 100;

    protected LinkedList<SessionTiming> sessionCreationTiming =
        new LinkedList<SessionTiming>();

    protected LinkedList<SessionTiming> sessionExpirationTiming =
        new LinkedList<SessionTiming>();


    /**
     * Number of sessions that have expired.
     */
    protected int expiredSessions = 0;


    /**
     * The set of currently active Sessions for this Manager, keyed by
     * session identifier.
     */
    protected Map<String, Session> sessions = new ConcurrentHashMap<String, Session>();

    // Number of sessions created by this manager
    protected int sessionCounter=0;

    protected volatile int maxActive=0;

    private final Object maxActiveUpdateLock = new Object();

    // number of duplicated session ids - anything >0 means we have problems
    protected int duplicates=0;

    protected boolean initialized=false;
    
    /**
     * Processing time during session expiration.
     */
    protected long processingTime = 0;

    /**
     * Iteration count for background processing.
     */
    private int count = 0;


    /**
     * Frequency of the session expiration, and related manager operations.
     * Manager operations will be done once for the specified amount of
     * backgrondProcess calls (ie, the lower the amount, the most often the
     * checks will occur).
     */
    protected int processExpiresFrequency = 6;

    /**
     * The string manager for this package.
     */
    protected static final StringManager sm = StringManager.getManager(Constants.Package);

    /**
     * The property change support for this component.
     */
    protected PropertyChangeSupport support = new PropertyChangeSupport(this);

    private Pattern sessionAttributeNamePattern;

    private Pattern sessionAttributeValueClassNamePattern;

    private boolean warnOnSessionAttributeFilterFailure;


    // ------------------------------------------------------------- Security classes

    private class PrivilegedSetRandomFile
            implements PrivilegedAction<Void>{

        private final String s;

        public PrivilegedSetRandomFile(String s) {
            this.s = s;
        }

        public Void run(){
            doSetRandomFile(s);
            return null;
        }
    }


    // ------------------------------------------------------------ Constructors

    public ManagerBase() {
        if (Globals.IS_SECURITY_ENABLED) {
            // Minimum set required for default distribution/persistence to work
            // plus String
            setSessionAttributeValueClassNameFilter(
                    "java\\.lang\\.(?:Boolean|Integer|Long|Number|String)");
            setWarnOnSessionAttributeFilterFailure(true);
        }
    }


    // -------------------------------------------------------------- Properties

    /**
     * Obtain the regular expression used to filter session attribute based on
     * attribute name. The regular expression is anchored so it must match the
     * entire name
     *
     * @return The regular expression currently used to filter attribute names.
     *         {@code null} means no filter is applied. If an empty string is
     *         specified then no names will match the filter and all attributes
     *         will be blocked.
     */
    public String getSessionAttributeNameFilter() {
        if (sessionAttributeNamePattern == null) {
            return null;
        }
        return sessionAttributeNamePattern.toString();
    }


    public void setSessionAttributeNameFilter(String sessionAttributeNameFilter) {
        if (sessionAttributeNameFilter == null || sessionAttributeNameFilter.length() == 0) {
            sessionAttributeNamePattern = null;
        } else {
            sessionAttributeNamePattern = Pattern.compile(sessionAttributeNameFilter);
        }
    }


    protected Pattern getSessionAttributeNamePattern() {
        return sessionAttributeNamePattern;
    }


    /**
     * Obtain the regular expression used to filter session attribute based on
     * the implementation class of the value. The regular expression is anchored
     * and must match the fully qualified class name.
     *
     * @return The regular expression currently used to filter class names.
     *         {@code null} means no filter is applied. If an empty string is
     *         specified then no names will match the filter and all attributes
     *         will be blocked.
     */
    public String getSessionAttributeValueClassNameFilter() {
        if (sessionAttributeValueClassNamePattern == null) {
            return null;
        }
        return sessionAttributeValueClassNamePattern.toString();
    }


    /**
     * Provides {@link #getSessionAttributeValueClassNameFilter()} as a
     * pre-compiled regular expression pattern.
     *
     * @return The pre-compiled pattern used to filter session attributes based
     *         on the implementation class name of the value. {@code null} means
     *         no filter is applied.
     */
    protected Pattern getSessionAttributeValueClassNamePattern() {
        return sessionAttributeValueClassNamePattern;
    }


    /**
     * Set the regular expression to use to filter classes used for session
     * attributes. The regular expression is anchored and must match the fully
     * qualified class name.
     *
     * @param sessionAttributeValueClassNameFilter The regular expression to use
     *            to filter session attributes based on class name. Use {@code
     *            null} if no filtering is required. If an empty string is
     *           specified then no names will match the filter and all
     *           attributes will be blocked.
     *
     * @throws PatternSyntaxException If the expression is not valid
     */
    public void setSessionAttributeValueClassNameFilter(String sessionAttributeValueClassNameFilter)
            throws PatternSyntaxException {
        if (sessionAttributeValueClassNameFilter == null ||
                sessionAttributeValueClassNameFilter.length() == 0) {
            sessionAttributeValueClassNamePattern = null;
        } else {
            sessionAttributeValueClassNamePattern =
                    Pattern.compile(sessionAttributeValueClassNameFilter);
        }
    }


    /**
     * Should a warn level log message be generated if a session attribute is
     * not persisted / replicated / restored.
     *
     * @return {@code true} if a warn level log message should be generated
     */
    public boolean getWarnOnSessionAttributeFilterFailure() {
        return warnOnSessionAttributeFilterFailure;
    }


    /**
     * Configure whether or not a warn level log message should be generated if
     * a session attribute is not persisted / replicated / restored.
     *
     * @param warnOnSessionAttributeFilterFailure {@code true} if the
     *            warn level message should be generated
     *
     */
    public void setWarnOnSessionAttributeFilterFailure(
            boolean warnOnSessionAttributeFilterFailure) {
        this.warnOnSessionAttributeFilterFailure = warnOnSessionAttributeFilterFailure;
    }


    /**
     * Return the message digest algorithm for this Manager.
     */
    public String getAlgorithm() {

        return (this.algorithm);

    }


    /**
     * Set the message digest algorithm for this Manager.
     *
     * @param algorithm The new message digest algorithm
     */
    public void setAlgorithm(String algorithm) {

        String oldAlgorithm = this.algorithm;
        this.algorithm = algorithm;
        support.firePropertyChange("algorithm", oldAlgorithm, this.algorithm);

    }


    /**
     * Return the Container with which this Manager is associated.
     */
    public Container getContainer() {
        return this.container;
    }


    public void setContainer(Container container) {
        if (this.container == container) {
            // NO-OP
            return;
        }
        if (initialized) {
            throw new IllegalStateException(sm.getString("managerBase.setContextNotNew"));
        }
        Container oldContainer = this.container;
        this.container = container;
        // TODO - delete the line below in Tomcat 9 onwards
        support.firePropertyChange("container", oldContainer, this.container);
    }


    /**
     * @return The name of the implementation class.
     */
    public String getClassName() {
        return this.getClass().getName();
    }


    /**
     * Return the MessageDigest object to be used for calculating
     * session identifiers.  If none has been created yet, initialize
     * one the first time this method is called.
     */
    public synchronized MessageDigest getDigest() {

        if (this.digest == null) {
            long t1=System.currentTimeMillis();
            if (log.isDebugEnabled())
                log.debug(sm.getString("managerBase.getting", algorithm));
            try {
                this.digest = MessageDigest.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                log.error(sm.getString("managerBase.digest", algorithm), e);
                try {
                    this.digest = MessageDigest.getInstance(DEFAULT_ALGORITHM);
                } catch (NoSuchAlgorithmException f) {
                    log.error(sm.getString("managerBase.digest",
                                     DEFAULT_ALGORITHM), e);
                    this.digest = null;
                }
            }
            if (log.isDebugEnabled())
                log.debug(sm.getString("managerBase.gotten"));
            long t2=System.currentTimeMillis();
            if( log.isDebugEnabled() )
                log.debug("getDigest() " + (t2-t1));
        }

        return (this.digest);

    }


    /**
     * Return the distributable flag for the sessions supported by
     * this Manager.
     */
    @Deprecated
    public boolean getDistributable() {
        Container container = getContainer();
        if (container instanceof Context) {
            return ((Context) container).getDistributable();
        }
        return false;
    }


    @Deprecated
    public void setDistributable(boolean distributable) {
        // NO-OP
    }


    /**
     * Return the entropy increaser value, or compute a semi-useful value
     * if this String has not yet been set.
     */
    public String getEntropy() {

        // Calculate a semi-useful value if this has not been set
        if (this.entropy == null) {
            // Use APR to get a crypto secure entropy value
            byte[] result = new byte[32];
            boolean apr = false;
            try {
                String methodName = "random";
                Class<?> paramTypes[] = new Class[2];
                paramTypes[0] = result.getClass();
                paramTypes[1] = int.class;
                Object paramValues[] = new Object[2];
                paramValues[0] = result;
                paramValues[1] = new Integer(32);
                Method method = Class.forName("org.apache.tomcat.jni.OS")
                    .getMethod(methodName, paramTypes);
                method.invoke(null, paramValues);
                apr = true;
            } catch (Throwable t) {
                // Ignore
            }
            if (apr) {
                try {
                    setEntropy(new String(result, "ISO-8859-1"));
                } catch (UnsupportedEncodingException ux) {
                    // ISO-8859-1 should always be supported
                    throw new Error(ux);
                }
            } else {
                setEntropy(this.toString());
            }
        }

        return (this.entropy);

    }


    /**
     * Set the entropy increaser value.
     *
     * @param entropy The new entropy increaser value
     */
    public void setEntropy(String entropy) {

        String oldEntropy = entropy;
        this.entropy = entropy;
        support.firePropertyChange("entropy", oldEntropy, this.entropy);

    }


    /**
     * Return descriptive information about this Manager implementation and
     * the corresponding version number, in the format
     * <code>&lt;description&gt;/&lt;version&gt;</code>.
     */
    @Deprecated
    public String getInfo() {
        return info;
    }


    /**
     * Return the default maximum inactive interval (in seconds)
     * for Sessions created by this Manager.
     */
    public int getMaxInactiveInterval() {
        Container container = getContainer();
        if (container instanceof Context) {
            return ((Context) container).getSessionTimeout();
        }
        return -1;
    }


    @Deprecated
    public void setMaxInactiveInterval(int interval) {
        // NO-OP
    }


    /**
     * Gets the session id length (in bytes) of Sessions created by
     * this Manager.
     *
     * @return The session id length
     */
    public int getSessionIdLength() {

        return (this.sessionIdLength);

    }


    /**
     * Sets the session id length (in bytes) for Sessions created by this
     * Manager.
     *
     * @param idLength The session id length
     */
    public void setSessionIdLength(int idLength) {

        int oldSessionIdLength = this.sessionIdLength;
        this.sessionIdLength = idLength;
        support.firePropertyChange("sessionIdLength",
                                   new Integer(oldSessionIdLength),
                                   new Integer(this.sessionIdLength));

    }


    /**
     * @return The descriptive short name of this Manager implementation.
     */
    public String getName() {

        return (name);

    }

    /** 
     * Use /dev/random-type special device. This is new code, but may reduce
     * the big delay in generating the random.
     *
     *  You must specify a path to a random generator file. Use /dev/urandom
     *  for linux ( or similar ) systems. Use /dev/random for maximum security
     *  ( it may block if not enough "random" exist ). You can also use
     *  a pipe that generates random.
     *
     *  The code will check if the file exists, and default to java Random
     *  if not found. There is a significant performance difference, very
     *  visible on the first call to getSession ( like in the first JSP )
     *  - so use it if available.
     */
    public void setRandomFile( String s ) {
        // as a hack, you can use a static file - and generate the same
        // session ids ( good for strange debugging )
        if (Globals.IS_SECURITY_ENABLED){
            AccessController.doPrivileged(new PrivilegedSetRandomFile(s));
        } else {
            doSetRandomFile(s);
        }
    }

    private void doSetRandomFile(String s) {
        DataInputStream is = null;
        try {
            if (s == null || s.length() == 0) {
                return;
            }
            File f = new File(s);
            if( ! f.exists() ) return;
            if( log.isDebugEnabled() ) {
                log.debug( "Opening " + s );
            }
            is = new DataInputStream( new FileInputStream(f));
            is.readLong();
        } catch( IOException ex ) {
            log.warn("Error reading " + s, ex);
            if (is != null) {
                try {
                    is.close();
                } catch (Exception ex2) {
                    log.warn("Failed to close " + s, ex2);
                }
                is = null;
            }
        } finally {
            DataInputStream oldIS = randomIS;
            if (is != null) {
                devRandomSource = s;
            } else {
                devRandomSource = null;
            }
            randomIS = is;
            if (oldIS != null) {
                try {
                    oldIS.close();
                } catch (Exception ex) {
                    log.warn("Failed to close RandomIS", ex);
                }
            }
        }
    }

    public String getRandomFile() {
        return devRandomSource;
    }


    /**
     * Return the random number generator instance we should use for
     * generating session identifiers.  If there is no such generator
     * currently defined, construct and seed a new one.
     */
    public Random getRandom() {
        if (this.random == null) {
            // Calculate the new random number generator seed
            long seed = System.currentTimeMillis();
            long t1 = seed;
            char entropy[] = getEntropy().toCharArray();
            for (int i = 0; i < entropy.length; i++) {
                long update = ((long) entropy[i]) << ((i % 8) * 8);
                seed ^= update;
            }
            try {
                // Construct and seed a new random number generator
                Class<?> clazz = Class.forName(randomClass);
                this.random = (Random) clazz.newInstance();
                this.random.setSeed(seed);
            } catch (Exception e) {
                // Fall back to the simple case
                log.error(sm.getString("managerBase.random", randomClass),
                        e);
                this.random = new java.util.Random();
                this.random.setSeed(seed);
            }
            if(log.isDebugEnabled()) {
                long t2=System.currentTimeMillis();
                if( (t2-t1) > 100 )
                    log.debug(sm.getString("managerBase.seeding", randomClass) + " " + (t2-t1));
            }
        }
        
        return this.random;
    }


    /**
     * Return the random number generator class name.
     */
    public String getRandomClass() {
        return this.randomClass;
    }


    /**
     * Set the random number generator class name.
     *
     * @param randomClass The new random number generator class name
     */
    public void setRandomClass(String randomClass) {
        String oldRandomClass = this.randomClass;
        this.randomClass = randomClass;
        support.firePropertyChange("randomClass", oldRandomClass, this.randomClass);
    }


    /**
     * Gets the number of sessions that have expired.
     *
     * @return Number of sessions that have expired
     */
    public int getExpiredSessions() {
        return expiredSessions;
    }


    /**
     * Sets the number of sessions that have expired.
     *
     * @param expiredSessions Number of sessions that have expired
     */
    public void setExpiredSessions(int expiredSessions) {
        this.expiredSessions = expiredSessions;
    }

    public long getProcessingTime() {
        return processingTime;
    }


    public void setProcessingTime(long processingTime) {
        this.processingTime = processingTime;
    }
    
    /**
     * @return The frequency of manager checks.
     */
    public int getProcessExpiresFrequency() {
        return this.processExpiresFrequency;
    }

    /**
     * Set the manager checks frequency.
     *
     * @param processExpiresFrequency the new manager checks frequency
     */
    public void setProcessExpiresFrequency(int processExpiresFrequency) {

        if (processExpiresFrequency <= 0) {
            return;
        }

        int oldProcessExpiresFrequency = this.processExpiresFrequency;
        this.processExpiresFrequency = processExpiresFrequency;
        support.firePropertyChange("processExpiresFrequency",
                                   new Integer(oldProcessExpiresFrequency),
                                   new Integer(this.processExpiresFrequency));
    }
    
    
    // --------------------------------------------------------- Public Methods

    /**
     * Implements the Manager interface, direct call to processExpires
     */
    public void backgroundProcess() {
        count = (count + 1) % processExpiresFrequency;
        if (count == 0)
            processExpires();
    }

    /**
     * Invalidate all sessions that have expired.
     */
    public void processExpires() {

        long timeNow = System.currentTimeMillis();
        Session sessions[] = findSessions();
        int expireHere = 0 ;
        
        if(log.isDebugEnabled())
            log.debug("Start expire sessions " + getName() + " at " + timeNow + " sessioncount " + sessions.length);
        for (int i = 0; i < sessions.length; i++) {
            if (sessions[i]!=null && !sessions[i].isValid()) {
                expireHere++;
            }
        }
        long timeEnd = System.currentTimeMillis();
        if(log.isDebugEnabled())
             log.debug("End expire sessions " + getName() + " processingTime " + (timeEnd - timeNow) + " expired sessions: " + expireHere);
        processingTime += ( timeEnd - timeNow );

    }

    public void destroy() {
        if( oname != null )
            Registry.getRegistry(null, null).unregisterComponent(oname);
        if (randomIS!=null) {
            try {
                randomIS.close();
            } catch (IOException ioe) {
                log.warn("Failed to close randomIS.");
            }
            randomIS=null;
        }

        initialized=false;
        oname = null;
    }
    
    public void init() {
        if( initialized ) return;
        initialized=true;        
        
        log = LogFactory.getLog(ManagerBase.class);
        
        if( oname==null ) {
            try {
                StandardContext ctx=(StandardContext)this.getContainer();
                domain=ctx.getEngineName();
                distributable = ctx.getDistributable();
                StandardHost hst=(StandardHost)ctx.getParent();
                String path = ctx.getPath();
                if (path.equals("")) {
                    path = "/";
                }   
                oname=new ObjectName(domain + ":type=Manager,path="
                + path + ",host=" + hst.getName());
                Registry.getRegistry(null, null).registerComponent(this, oname, null );
            } catch (Exception e) {
                log.error("Error registering ",e);
            }
        }
        
        // Initialize random number generation
        getRandomBytes(new byte[16]);
        
        if (!(container instanceof Context)) {
            throw new IllegalStateException(sm.getString("managerBase.contextNull"));
        }

        // Ensure caches for timing stats are the right size by filling with
        // nulls.
        while (sessionCreationTiming.size() < TIMING_STATS_CACHE_SIZE) {
            sessionCreationTiming.add(null);
        }
        while (sessionExpirationTiming.size() < TIMING_STATS_CACHE_SIZE) {
            sessionExpirationTiming.add(null);
        }

        if(log.isDebugEnabled())
            log.debug("Registering " + oname );
               
    }

    /**
     * Add this Session to the set of active Sessions for this Manager.
     *
     * @param session Session to be added
     */
    public void add(Session session) {

        sessions.put(session.getIdInternal(), session);
        int size = sessions.size();
        if( size > maxActive ) {
            synchronized(maxActiveUpdateLock) {
                if( size > maxActive ) {
                    maxActive = size;
                }
            }
        }
    }


    /**
     * Add a property change listener to this component.
     *
     * @param listener The listener to add
     */
    public void addPropertyChangeListener(PropertyChangeListener listener) {

        support.addPropertyChangeListener(listener);

    }


    /**
     * Construct and return a new session object, based on the default
     * settings specified by this Manager's properties.  The session
     * id will be assigned by this method, and available via the getId()
     * method of the returned session.  If a new session cannot be created
     * for any reason, return <code>null</code>.
     * 
     * @exception IllegalStateException if a new session cannot be
     *  instantiated for any reason
     * @deprecated
     */
    @Deprecated
    public Session createSession() {
        return createSession(null);
    }
    
    
    /**
     * Construct and return a new session object, based on the default
     * settings specified by this Manager's properties.  The session
     * id specified will be used as the session id.  
     * If a new session cannot be created for any reason, return 
     * <code>null</code>.
     * 
     * @param sessionId The session id which should be used to create the
     *  new session; if <code>null</code>, a new session id will be
     *  generated
     * @exception IllegalStateException if a new session cannot be
     *  instantiated for any reason
     */
    public Session createSession(String sessionId) {
        
        // Recycle or create a Session instance
        Session session = createEmptySession();

        // Initialize the properties of the new session and return it
        session.setNew(true);
        session.setValid(true);
        session.setCreationTime(System.currentTimeMillis());
        session.setMaxInactiveInterval(((Context) getContainer()).getSessionTimeout() * 60);
        if (sessionId == null) {
            sessionId = generateSessionId();
        // FIXME WHy we need no duplication check?
        /*         
             synchronized (sessions) {
                while (sessions.get(sessionId) != null) { // Guarantee
                    // uniqueness
                    duplicates++;
                    sessionId = generateSessionId();
                }
            }
        */
            
            // FIXME: Code to be used in case route replacement is needed
            /*
        } else {
            String jvmRoute = getJvmRoute();
            if (getJvmRoute() != null) {
                String requestJvmRoute = null;
                int index = sessionId.indexOf(".");
                if (index > 0) {
                    requestJvmRoute = sessionId
                            .substring(index + 1, sessionId.length());
                }
                if (requestJvmRoute != null && !requestJvmRoute.equals(jvmRoute)) {
                    sessionId = sessionId.substring(0, index) + "." + jvmRoute;
                }
            }
            */
        }
        session.setId(sessionId);
        sessionCounter++;

        SessionTiming timing = new SessionTiming(session.getCreationTime(), 0);
        synchronized (sessionCreationTiming) {
            sessionCreationTiming.add(timing);
            sessionCreationTiming.poll();
        }
        return (session);

    }
    
    
    /**
     * Get a session from the recycled ones or create a new empty one.
     * The PersistentManager manager does not need to create session data
     * because it reads it from the Store.
     */
    public Session createEmptySession() {
        return (getNewSession());
    }


    /**
     * Return the active Session, associated with this Manager, with the
     * specified session id (if any); otherwise return <code>null</code>.
     *
     * @param id The session id for the session to be returned
     *
     * @exception IllegalStateException if a new session cannot be
     *  instantiated for any reason
     * @exception IOException if an input/output error occurs while
     *  processing this request
     */
    public Session findSession(String id) throws IOException {
        if (id == null) {
            return null;
        }
        return sessions.get(id);
    }


    /**
     * Return the set of active Sessions associated with this Manager.
     * If this Manager has no active Sessions, a zero-length array is returned.
     */
    public Session[] findSessions() {
        return sessions.values().toArray(new Session[0]);
    }


    /**
     * Remove this Session from the active Sessions for this Manager.
     *
     * @param session Session to be removed
     */
    public void remove(Session session) {
        sessions.remove(session.getIdInternal());
    }


    /**
     * Remove a property change listener from this component.
     *
     * @param listener The listener to remove
     */
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        support.removePropertyChangeListener(listener);
    }


    /**
     * Change the session ID of the current session to a new randomly generated
     * session ID.
     * 
     * @param session   The session to change the session ID for
     */
    public void changeSessionId(Session session) {
        String oldId = session.getIdInternal();
        session.setId(generateSessionId(), false);
        String newId = session.getIdInternal();
        if (container instanceof ContainerBase) {
            ((ContainerBase)container).fireContainerEvent(
                    Context.CHANGE_SESSION_ID_EVENT,
                    new String[] {oldId, newId});
        }
    }
    
    
    /**
     * {@inheritDoc}
     * <p>
     * This implementation excludes session attributes from distribution if the:
     * <ul>
     * <li>attribute name matches {@link #getSessionAttributeNameFilter()}</li>
     * </ul>
     */
    public boolean willAttributeDistribute(String name, Object value) {
        Pattern sessionAttributeNamePattern = getSessionAttributeNamePattern();
        if (sessionAttributeNamePattern != null) {
            if (!sessionAttributeNamePattern.matcher(name).matches()) {
                if (getWarnOnSessionAttributeFilterFailure() || log.isDebugEnabled()) {
                    String msg = sm.getString("managerBase.sessionAttributeNameFilter",
                            name, sessionAttributeNamePattern);
                    if (getWarnOnSessionAttributeFilterFailure()) {
                        log.warn(msg);
                    } else {
                        log.debug(msg);
                    }
                }
                return false;
            }
        }

        Pattern sessionAttributeValueClassNamePattern = getSessionAttributeValueClassNamePattern();
        if (value != null && sessionAttributeValueClassNamePattern != null) {
            if (!sessionAttributeValueClassNamePattern.matcher(
                    value.getClass().getName()).matches()) {
                if (getWarnOnSessionAttributeFilterFailure() || log.isDebugEnabled()) {
                    String msg = sm.getString("managerBase.sessionAttributeValueClassNameFilter",
                            name, value.getClass().getName(), sessionAttributeNamePattern);
                    if (getWarnOnSessionAttributeFilterFailure()) {
                        log.warn(msg);
                    } else {
                        log.debug(msg);
                    }
                }
                return false;
            }
        }

        return true;
    }


    // ------------------------------------------------------ Protected Methods

    /**
     * Get new session class to be used in the doLoad() method.
     */
    protected StandardSession getNewSession() {
        return new StandardSession(this);
    }


    protected void getRandomBytes(byte bytes[]) {
        // Generate a byte array containing a session identifier
        if (devRandomSource != null && randomIS == null) {
            setRandomFile(devRandomSource);
        }
        if (randomIS != null) {
            try {
                int len = randomIS.read(bytes);
                if (len == bytes.length) {
                    return;
                }
                if(log.isDebugEnabled())
                    log.debug("Got " + len + " " + bytes.length );
            } catch (Exception ex) {
                // Ignore
            }
            devRandomSource = null;
            
            try {
                randomIS.close();
            } catch (Exception e) {
                log.warn("Failed to close randomIS.");
            }
            
            randomIS = null;
        }
        getRandom().nextBytes(bytes);
    }


    /**
     * Generate and return a new session identifier.
     */
    protected synchronized String generateSessionId() {

        byte random[] = new byte[16];
        String jvmRoute = getJvmRoute();
        String result = null;

        // Render the result as a String of hexadecimal digits
        StringBuffer buffer = new StringBuffer();
        do {
            int resultLenBytes = 0;
            if (result != null) {
                buffer = new StringBuffer();
                duplicates++;
            }

            while (resultLenBytes < this.sessionIdLength) {
                getRandomBytes(random);
                random = getDigest().digest(random);
                for (int j = 0;
                j < random.length && resultLenBytes < this.sessionIdLength;
                j++) {
                    byte b1 = (byte) ((random[j] & 0xf0) >> 4);
                    byte b2 = (byte) (random[j] & 0x0f);
                    if (b1 < 10)
                        buffer.append((char) ('0' + b1));
                    else
                        buffer.append((char) ('A' + (b1 - 10)));
                    if (b2 < 10)
                        buffer.append((char) ('0' + b2));
                    else
                        buffer.append((char) ('A' + (b2 - 10)));
                    resultLenBytes++;
                }
            }
            if (jvmRoute != null) {
                buffer.append('.').append(jvmRoute);
            }
            result = buffer.toString();
        } while (sessions.containsKey(result));
        return (result);

    }


    // ------------------------------------------------------ Protected Methods


    /**
     * Retrieve the enclosing Engine for this Manager.
     *
     * @return an Engine object (or null).
     */
    public Engine getEngine() {
        Engine e = null;
        for (Container c = getContainer(); e == null && c != null ; c = c.getParent()) {
            if (c instanceof Engine) {
                e = (Engine)c;
            }
        }
        return e;
    }


    /**
     * Retrieve the JvmRoute for the enclosing Engine.
     * @return the JvmRoute or null.
     */
    public String getJvmRoute() {
        Engine e = getEngine();
        return e == null ? null : e.getJvmRoute();
    }


    // -------------------------------------------------------- Package Methods


    public void setSessionCounter(int sessionCounter) {
        this.sessionCounter = sessionCounter;
    }


    /** 
     * Total sessions created by this manager.
     *
     * @return sessions created
     */
    public int getSessionCounter() {
        return sessionCounter;
    }


    /** 
     * Number of duplicated session IDs generated by the random source.
     * Anything bigger than 0 means problems.
     *
     * @return The count of duplicates
     */
    public int getDuplicates() {
        return duplicates;
    }


    public void setDuplicates(int duplicates) {
        this.duplicates = duplicates;
    }


    /** 
     * Returns the number of active sessions
     *
     * @return number of sessions active
     */
    public int getActiveSessions() {
        return sessions.size();
    }


    /**
     * Max number of concurrent active sessions
     *
     * @return The highest number of concurrent active sessions
     */
    public int getMaxActive() {
        return maxActive;
    }


    public void setMaxActive(int maxActive) {
        synchronized (maxActiveUpdateLock) {
            this.maxActive = maxActive;
        }
    }


    /**
     * Gets the longest time (in seconds) that an expired session had been
     * alive.
     *
     * @return Longest time (in seconds) that an expired session had been
     * alive.
     */
    public int getSessionMaxAliveTime() {
        return sessionMaxAliveTime;
    }


    /**
     * Sets the longest time (in seconds) that an expired session had been
     * alive.
     *
     * @param sessionMaxAliveTime Longest time (in seconds) that an expired
     * session had been alive.
     */
    public void setSessionMaxAliveTime(int sessionMaxAliveTime) {
        this.sessionMaxAliveTime = sessionMaxAliveTime;
    }


    /**
     * Gets the average time (in seconds) that expired sessions had been
     * alive.
     *
     * @return Average time (in seconds) that expired sessions had been
     * alive.
     */
    public int getSessionAverageAliveTime() {
        return sessionAverageAliveTime;
    }


    /**
     * Sets the average time (in seconds) that expired sessions had been
     * alive.
     *
     * @param sessionAverageAliveTime Average time (in seconds) that expired
     * sessions had been alive.
     */
    public void setSessionAverageAliveTime(int sessionAverageAliveTime) {
        this.sessionAverageAliveTime = sessionAverageAliveTime;
    }


    /**
     * Gets the current rate of session creation (in session per minute) based
     * on the creation time of the previous 100 sessions created. If less than
     * 100 sessions have been created then all available data is used.
     * 
     * @return  The current rate (in sessions per minute) of session creation
     */
    public int getSessionCreateRate() {
        long now = System.currentTimeMillis();
        // Copy current stats
        List<SessionTiming> copy = new ArrayList<SessionTiming>();
        synchronized (sessionCreationTiming) {
            copy.addAll(sessionCreationTiming);
        }
        
        // Init
        long oldest = now;
        int counter = 0;
        int result = 0;
        Iterator<SessionTiming> iter = copy.iterator();
        
        // Calculate rate
        while (iter.hasNext()) {
            SessionTiming timing = iter.next();
            if (timing != null) {
                counter++;
                if (timing.getTimestamp() < oldest) {
                    oldest = timing.getTimestamp();
                }
            }
        }
        if (counter > 0) {
            if (oldest < now) {
                result = (int) ((1000*60*counter)/(now - oldest));
            } else {
                result = Integer.MAX_VALUE;
            }
        }
        return result;
    }
    

    /**
     * Gets the current rate of session expiration (in session per minute) based
     * on the expiry time of the previous 100 sessions expired. If less than
     * 100 sessions have expired then all available data is used.
     * 
     * @return  The current rate (in sessions per minute) of session expiration
     */
    public int getSessionExpireRate() {
        long now = System.currentTimeMillis();
        // Copy current stats
        List<SessionTiming> copy = new ArrayList<SessionTiming>();
        synchronized (sessionExpirationTiming) {
            copy.addAll(sessionExpirationTiming);
        }
        
        // Init
        long oldest = now;
        int counter = 0;
        int result = 0;
        Iterator<SessionTiming> iter = copy.iterator();
        
        // Calculate rate
        while (iter.hasNext()) {
            SessionTiming timing = iter.next();
            if (timing != null) {
                counter++;
                if (timing.getTimestamp() < oldest) {
                    oldest = timing.getTimestamp();
                }
            }
        }
        if (counter > 0) {
            if (oldest < now) {
                result = (int) ((1000*60*counter)/(now - oldest));
            } else {
                // Better than reporting zero
                result = Integer.MAX_VALUE;
            }
        }
        return result;
    }


    /** 
     * For debugging.
     *
     * @return A space separated list of all session IDs currently active
     */
    public String listSessionIds() {
        StringBuilder sb = new StringBuilder();
        Iterator<String> keys = sessions.keySet().iterator();
        while (keys.hasNext()) {
            sb.append(keys.next()).append(" ");
        }
        return sb.toString();
    }


    /** 
     * For debugging.
     *
     * @param sessionId The ID for the session of interest
     * @param key       The key for the attribute to obtain
     *
     * @return The attribute value for the specified session, if found, null
     *         otherwise
     */
    public String getSessionAttribute( String sessionId, String key ) {
        Session s = sessions.get(sessionId);
        if( s==null ) {
            if(log.isInfoEnabled())
                log.info("Session not found " + sessionId);
            return null;
        }
        Object o=s.getSession().getAttribute(key);
        if( o==null ) return null;
        return o.toString();
    }


    /**
     * Returns information about the session with the given session id.
     * 
     * <p>The session information is organized as a HashMap, mapping 
     * session attribute names to the String representation of their values.
     *
     * @param sessionId Session id
     * 
     * @return HashMap mapping session attribute names to the String
     * representation of their values, or null if no session with the
     * specified id exists, or if the session does not have any attributes
     */
    public HashMap<String,Object> getSession(String sessionId) {
        Session s = sessions.get(sessionId);
        if (s == null) {
            if (log.isInfoEnabled()) {
                log.info("Session not found " + sessionId);
            }
            return null;
        }

        @SuppressWarnings("unchecked")
        Enumeration<String> ee = s.getSession().getAttributeNames();
        if (ee == null || !ee.hasMoreElements()) {
            return null;
        }

        HashMap<String,Object> map = new HashMap<String,Object>();
        while (ee.hasMoreElements()) {
            String attrName = ee.nextElement();
            map.put(attrName, getSessionAttribute(sessionId, attrName));
        }

        return map;
    }


    public void expireSession( String sessionId ) {
        Session s = sessions.get(sessionId);
        if (s == null) {
            if(log.isInfoEnabled())
                log.info("Session not found " + sessionId);
            return;
        }
        s.expire();
    }

    public long getLastAccessedTimestamp( String sessionId ) {
        Session s = sessions.get(sessionId);
        if (s == null) {
            return -1;
        }
        return s.getLastAccessedTime();
    }
  
    public String getLastAccessedTime( String sessionId ) {
        Session s = sessions.get(sessionId);
        if (s == null) {
            if(log.isInfoEnabled())
                log.info("Session not found " + sessionId);
            return "";
        }
        return new Date(s.getLastAccessedTime()).toString();
    }

    public String getCreationTime( String sessionId ) {
        Session s = sessions.get(sessionId);
        if (s == null) {
            if(log.isInfoEnabled())
                log.info("Session not found " + sessionId);
            return "";
        }
        return new Date(s.getCreationTime()).toString();
    }

    public long getCreationTimestamp( String sessionId ) {
        Session s = sessions.get(sessionId);
        if (s == null) {
            return -1;
        }
        return s.getCreationTime();
    }

    // -------------------- JMX and Registration  --------------------
    protected String domain;
    protected ObjectName oname;
    protected MBeanServer mserver;

    public ObjectName getObjectName() {
        return oname;
    }

    public String getDomain() {
        return domain;
    }

    public ObjectName preRegister(MBeanServer server,
                                  ObjectName name) throws Exception {
        oname=name;
        mserver=server;
        domain=name.getDomain();
        return name;
    }

    public void postRegister(Boolean registrationDone) {
    }

    public void preDeregister() throws Exception {
    }

    public void postDeregister() {
    }

    // ----------------------------------------------------------- Inner classes
    
    protected static final class SessionTiming {
        private long timestamp;
        private int duration;
        
        public SessionTiming(long timestamp, int duration) {
            this.timestamp = timestamp;
            this.duration = duration;
        }
        
        /**
         * @return Time stamp associated with this piece of timing information
         *         in milliseconds.
         */
        public long getTimestamp() {
            return timestamp;
        }
        
        /**
         * @return Duration associated with this piece of timing information in
         *         seconds.
         */
        public int getDuration() {
            return duration;
        }
    }
}
