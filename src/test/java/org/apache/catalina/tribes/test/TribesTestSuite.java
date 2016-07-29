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
package org.apache.catalina.tribes.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import org.apache.catalina.tribes.group.TestGroupChannelMemberArrival;
import org.apache.catalina.tribes.group.TestGroupChannelOptionFlag;
import org.apache.catalina.tribes.group.TestGroupChannelStartStop;
import org.apache.catalina.tribes.group.interceptors.TestOrderInterceptor;
import org.apache.catalina.tribes.group.interceptors.TestTcpFailureDetector;
import org.apache.catalina.tribes.membership.TestMemberImplSerialization;
import org.apache.catalina.tribes.test.channel.TestDataIntegrity;

@RunWith(Suite.class)
@SuiteClasses({
        TestGroupChannelStartStop.class,
        TestGroupChannelOptionFlag.class,
        TestMemberImplSerialization.class,
        TestGroupChannelMemberArrival.class,
        TestTcpFailureDetector.class,
        TestDataIntegrity.class,
        TestOrderInterceptor.class
})
public class TribesTestSuite {

}
