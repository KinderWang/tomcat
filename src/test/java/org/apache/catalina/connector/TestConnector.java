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
package org.apache.catalina.connector;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;

/**
 * Test cases for {@link Connector}.
 */
public class TestConnector extends TomcatBaseTest {

    @Test
    public void testPort() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        Connector connector1 = tomcat.getConnector();
        connector1.setPort(0);

        tomcat.start();

        int localPort1 = connector1.getLocalPort();

        assertTrue(localPort1 > 0);
    }
}
