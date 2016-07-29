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
package org.apache.catalina.tribes.io;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestXByteBuffer {

    // In Tomcat 6 the testEmptyArray() test fails with a java.io.EOFException.
    //
    // Backporting r1143022 (support for 0-length array in deserialize())
    // to Tomcat 6 is probably a bad idea, as
    //
    // 1. All valid use cases already check for (length == 0) case before
    // calling deserialize(), so adding a second check there is redundant
    //
    // 2. It will change behaviour of GroupChannel.messageReceived(),
    // as deserialize() call there will no longer fail with an exception.
    //
    // The change will be that instead of logging an error and returning
    // doing nothing, the messageReceived() method will go on and will notify
    // a channelListener. I do not know whether the listener is able to handle
    // a null argument.
    //
    // @Test
    // public void testEmptyArray() throws Exception {
    //   Object obj = XByteBuffer.deserialize(new byte[0]);
    //   assertNull(obj);
    // }

    @Test
    public void testSerializationString() throws Exception {
        String test = "This is as test.";
        byte[] msg = XByteBuffer.serialize(test);
        Object obj = XByteBuffer.deserialize(msg);
        assertTrue(obj instanceof String);
        assertEquals(test, obj);
    }

}
