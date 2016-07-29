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

import java.net.InetAddress;
import java.net.URLEncoder;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.tomcat.util.net.AbstractEndpoint;

public abstract class AbstractProtocol implements ProtocolHandler {

    /**
     * Counter used to generate unique JMX names for connectors using automatic
     * port binding.
     */
    private static final AtomicInteger nameCounter = new AtomicInteger(0);

    /**
     * Unique ID for this connector. Only used if the connector is configured
     * to use a random port as the port will change if stop(), start() is
     * called.
     */
    private int nameIndex = 0;


    protected abstract AbstractEndpoint getEndpoint();

    public int getMaxHeaderCount() {
        return getEndpoint().getMaxHeaderCount();
    }
    public void setMaxHeaderCount(int maxHeaderCount) {
        getEndpoint().setMaxHeaderCount(maxHeaderCount);
    }

    public int getLocalPort() {
        return getEndpoint().getLocalPort();
    }

    public synchronized int getNameIndex() {
        if (nameIndex == 0) {
            nameIndex = nextNameIndex();
        }
        return nameIndex;
    }

    public static int nextNameIndex() {
        return nameCounter.incrementAndGet();
    }

    /**
     * An utility method, used to implement getName() in subclasses.
     */
    protected String createName(String prefix, InetAddress address, int port) {
        StringBuilder name = new StringBuilder(prefix);
        name.append('-');
        if (address != null) {
            String strAddr = address.toString();
            if (strAddr.startsWith("/")) {
                strAddr = strAddr.substring(1);
            }
            name.append(URLEncoder.encode(strAddr)).append('-');
        }
        if (port == 0) {
            // Auto binding is in use. Check if port is known
            name.append("auto-");
            name.append(getNameIndex());
            port = getLocalPort();
            if (port != -1) {
                name.append('-');
                name.append(port);
            }
        } else {
            name.append(port);
        }
        return name.toString();
    }
}
