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


import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.digester.Rule;
import org.xml.sax.Attributes;
import org.apache.catalina.Service;
import org.apache.catalina.Executor;
import org.apache.tomcat.util.IntrospectionUtils;
import java.lang.reflect.Method;
import org.apache.juli.logging.LogFactory;
import org.apache.juli.logging.Log;



/**
 * Rule implementation that creates a connector.
 */

public class ConnectorCreateRule extends Rule {

    protected static Log log = LogFactory.getLog(ConnectorCreateRule.class);
    // --------------------------------------------------------- Public Methods


    /**
     * Process the beginning of this element.
     *
     * @param attributes The attribute list of this element
     */
    public void begin(Attributes attributes) throws Exception {
        Service svc = (Service)digester.peek();
        Executor ex = null;
        if ( attributes.getValue("executor")!=null ) {
            ex = svc.getExecutor(attributes.getValue("executor"));
        }
        Connector con = new Connector(attributes.getValue("protocol"));
        if ( ex != null )  _setExecutor(con,ex);
        
        digester.push(con);
    }
    
    public void _setExecutor(Connector con, Executor ex) throws Exception {
        Method m = IntrospectionUtils.findMethod(con.getProtocolHandler().getClass(),"setExecutor",new Class[] {java.util.concurrent.Executor.class});
        if (m!=null) {
            m.invoke(con.getProtocolHandler(), new Object[] {ex});
        }else {
            log.warn("Connector ["+con+"] does not support external executors. Method setExecutor(java.util.concurrent.Executor) not found.");
        }
    }


    /**
     * Process the end of this element.
     */
    public void end() throws Exception {
        Object top = digester.pop();
    }


}
