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

import java.util.concurrent.atomic.AtomicReference;

import org.apache.catalina.core.StandardServer;


/**
 * <p><strong>ServerFactory</strong> allows the registration of the
 * (singleton) <code>Server</code> instance for this JVM, so that it
 * can be accessed independently of any existing reference to the
 * component hierarchy.  This is important for administration tools
 * that are built around the internal component implementation classes.
 *
 * @author Craig R. McClanahan
 *
 */

public class ServerFactory {


    // ------------------------------------------------------- Static Variables


    /**
     * The singleton <code>Server</code> instance for this JVM.
     */
    private static final AtomicReference<Server> server = new AtomicReference<Server>();


    // --------------------------------------------------------- Public Methods


    /**
     * Return the singleton <code>Server</code> instance for this JVM.
     */
    public static Server getServer() {
        return getServer(true);
    }


    /**
     * Return the singleton <code>Server</code> instance for this JVM.
     *
     * @param create
     *            <code>true</code> to create a server if none is available and
     *            always return a <code>Server</code> instance,
     *            <code>false</code> to peek the current value and return
     *            <code>null</code> if no server has been created
     * @return Server instance or null
     */
    @SuppressWarnings("unused")
    public static Server getServer(boolean create) {
        Server s = server.get();
        if (s == null && create) {
            // Note that StandardServer() constructor calls setServer()
            new StandardServer();
            s = server.get();
        }
        return s;
    }


    /**
     * Set the singleton <code>Server</code> instance for this JVM.  This
     * method must <strong>only</strong> be called from a constructor of
     * the (singleton) <code>Server</code> instance that is created for
     * this execution of Catalina.
     *
     * @param theServer The new singleton instance
     */
    public static void setServer(Server theServer) {

        server.compareAndSet(null, theServer);

    }


    /**
     * Clears the singleton <code>Server</code> instance for this JVM. Allows to
     * run several instances of Tomcat sequentially in the same JVM. Unit tests
     * use this feature.
     */
    public static void clear() {
        server.set(null);
    }
}
