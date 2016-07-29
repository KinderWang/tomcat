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

import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.apache.catalina.core.StandardServer;

public class TestServerFactory {

    @After
    public void tearDown() {
        ServerFactory.clear();
    }

    @Test
    public void test1() {
        // Assert initial state of the test
        assertNull(ServerFactory.getServer(false));

        // Assert that ServerFactory.getServer() creates a server
        assertTrue(ServerFactory.getServer() instanceof StandardServer);

        ServerFactory.clear();
        assertNull(ServerFactory.getServer(false));

        // Assert that StandardServer() constructor called setServer()
        Server s = new StandardServer();
        assertEquals(s, ServerFactory.getServer(false));

        assertEquals(s, ServerFactory.getServer());
        assertEquals(s, ServerFactory.getServer(true));
    }
}
