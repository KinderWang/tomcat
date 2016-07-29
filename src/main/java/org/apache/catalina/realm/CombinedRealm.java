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

package org.apache.catalina.realm;

import java.security.Principal;

import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.management.ObjectName;

import org.apache.catalina.Container;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Realm;
import org.apache.catalina.util.StringManager;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Realm implementation that contains one or more realms. Authentication is
 * attempted for each realm in the order they were configured. If any realm
 * authenticates the user then the authentication succeeds. When combining
 * realms usernames should be unique across all combined realms.
 */
public class CombinedRealm extends RealmBase {

    private static Log log = LogFactory.getLog(CombinedRealm.class);

    /**
     * The string manager for this package.
     */
    protected static StringManager sm =
        StringManager.getManager(Constants.Package);
    
    /**
     * The list of Realms contained by this Realm.
     */
    protected List<Realm> realms = new LinkedList<Realm>();


    /**
     * Add a realm to the list of realms that will be used to authenticate
     * users.
     */
    public void addRealm(Realm theRealm) {
        realms.add(theRealm);
        
        if (log.isDebugEnabled()) {
            sm.getString("combinedRealm.addRealm", theRealm.getInfo(), 
                    Integer.toString(realms.size()));
        }
    }


    /**
     * Return the set of Realms that this Realm is wrapping
     */
    public ObjectName[] getRealms() {
        ObjectName[] result = new ObjectName[realms.size()];
        for (Realm realm : realms) {
            if (realm instanceof RealmBase) {
                result[realms.indexOf(realm)] =
                    ((RealmBase) realm).getObjectName();
            }
        }
        return result;
    }


    /**
     * Return the Principal associated with the specified username and
     * credentials, if there is one; otherwise return <code>null</code>.
     *
     * @param username Username of the Principal to look up
     * @param credentials Password or other credentials to use in
     *  authenticating this username
     */
    @Override
    public Principal authenticate(String username, byte[] credentials) {
        Principal authenticatedUser = null;
        
        for (Realm realm : realms) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("combinedRealm.authStart", username, realm.getInfo()));
            }
            
            authenticatedUser = realm.authenticate(username, credentials);
            
            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("combinedRealm.authFail", username, realm.getInfo()));
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("combinedRealm.authSucess", username, realm.getInfo()));
                }
                break;
            }
        }
        return authenticatedUser;
    }


    /**
     * Return the Principal associated with the specified username, which
     * matches the digest calculated using the given parameters using the
     * method described in RFC 2069; otherwise return <code>null</code>.
     *
     * @param username Username of the Principal to look up
     * @param clientDigest Digest which has been submitted by the client
     * @param once Unique (or supposedly unique) token which has been used
     * for this request
     * @param realmName Realm name
     * @param md5a2 Second MD5 digest used to calculate the digest :
     * MD5(Method + ":" + uri)
     */
    @Override
    public Principal authenticate(String username, String clientDigest,
            String once, String nc, String cnonce, String qop,
            String realmName, String md5a2) {
        Principal authenticatedUser = null;
        
        for (Realm realm : realms) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("combinedRealm.authStart", username, realm.getInfo()));
            }

            authenticatedUser = realm.authenticate(username, clientDigest, once,
                    nc, cnonce, qop, realmName, md5a2);

            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("combinedRealm.authFail", username, realm.getInfo()));
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("combinedRealm.authSucess", username, realm.getInfo()));
                }
                break;
            }
        }
        return authenticatedUser;
    }


    /**
     * Return the Principal associated with the specified username and
     * credentials, if there is one; otherwise return <code>null</code>.
     *
     * @param username Username of the Principal to look up
     * @param credentials Password or other credentials to use in
     *  authenticating this username
     */
    @Override
    public Principal authenticate(String username, String credentials) {
        Principal authenticatedUser = null;
        
        for (Realm realm : realms) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("combinedRealm.authStart", username, realm.getInfo()));
            }

            authenticatedUser = realm.authenticate(username, credentials);

            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("combinedRealm.authFail", username, realm.getInfo()));
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("combinedRealm.authSucess", username, realm.getInfo()));
                }
                break;
            }
        }
        return authenticatedUser;
    }


    /**
     * Set the Container with which this Realm has been associated.
     *
     * @param container The associated Container
     */
    @Override
    public void setContainer(Container container) {
        for(Realm realm : realms) {
            // Set the realmPath for JMX naming
            if (realm instanceof RealmBase) {
                ((RealmBase) realm).setRealmPath(
                        getRealmPath() + "/realm" + realms.indexOf(realm));
            }
            
            // Set the container for sub-realms. Mainly so logging works.
            realm.setContainer(container);
        }
        super.setContainer(container);
    }


    /**
     * Prepare for the beginning of active use of the public methods of this
     * component.  This method should be called before any of the public
     * methods of this component are utilized.  It should also send a
     * LifecycleEvent of type START_EVENT to any registered listeners.
     *
     * @exception LifecycleException if this component detects a fatal error
     *  that prevents this component from being used
     */
    @Override
    public void start() throws LifecycleException {
        // Start 'sub-realms' then this one
    	Iterator<Realm> iter = realms.iterator();
        
        while (iter.hasNext()) {
            Realm realm = iter.next();
            if (realm instanceof Lifecycle) {
                try {
                    ((Lifecycle) realm).start();
                } catch (LifecycleException e) {
                    // If realm doesn't start can't authenticate against it
                    iter.remove();
                    log.error(sm.getString("combinedRealm.realmStartFail",
                            realm.getInfo()), e);
                }
            }
        }
        super.start();
    }


    /**
     * Gracefully terminate the active use of the public methods of this
     * component.  This method should be the last one called on a given
     * instance of this component.  It should also send a LifecycleEvent
     * of type STOP_EVENT to any registered listeners.
     *
     * @exception LifecycleException if this component detects a fatal error
     *  that needs to be reported
     */
    @Override
    public void stop() throws LifecycleException {
        // Stop this realm, then the sub-realms (reverse order to start)
        super.stop();
        for (Realm realm : realms) {
            if (realm instanceof Lifecycle) {
                ((Lifecycle) realm).stop();
            }
        }        
    }

    /**
     * Delegate the backgroundProcess call to all sub-realms.
     */
    @Override
    public void backgroundProcess() {
        super.backgroundProcess();

        for (Realm r : realms) {
            r.backgroundProcess();
        }
    }

    /**
     * Return the Principal associated with the specified chain of X509
     * client certificates.  If there is none, return <code>null</code>.
     *
     * @param certs Array of client certificates, with the first one in
     *  the array being the certificate of the client itself.
     */
    @Override
    public Principal authenticate(X509Certificate[] certs) {
        Principal authenticatedUser = null;
        String username = null;
        if (certs != null && certs.length >0) {
            username = certs[0].getSubjectDN().getName();
        }
        
        for (Realm realm : realms) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("combinedRealm.authStart", username, realm.getInfo()));
            }

            authenticatedUser = realm.authenticate(certs);

            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("combinedRealm.authFail", username, realm.getInfo()));
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("combinedRealm.authSucess", username, realm.getInfo()));
                }
                break;
            }
        }
        return authenticatedUser;
    }

    @Override
    protected String getName() {
        // This method should never be called
        // Stack trace will show where this was called from
        UnsupportedOperationException uoe =
            new UnsupportedOperationException(
                    sm.getString("combinedRealm.getName"));
        log.error(sm.getString("combinedRealm.unexpectedMethod"), uoe);
        throw uoe;
    }

    @Override
    protected String getPassword(String username) {
        // This method should never be called
        // Stack trace will show where this was called from
        UnsupportedOperationException uoe =
            new UnsupportedOperationException(
                    sm.getString("combinedRealm.getPassword"));
        log.error(sm.getString("combinedRealm.unexpectedMethod"), uoe);
        throw uoe;
    }

    @Override
    protected Principal getPrincipal(String username) {
        // This method should never be called
        // Stack trace will show where this was called from
        UnsupportedOperationException uoe =
            new UnsupportedOperationException(
                    sm.getString("combinedRealm.getPrincipal"));
        log.error(sm.getString("combinedRealm.unexpectedMethod"), uoe);
        throw uoe;
    }

}
