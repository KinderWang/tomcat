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

package org.apache.catalina.core;

import java.util.Collection;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.catalina.Executor;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.util.LifecycleSupport;
import java.util.concurrent.RejectedExecutionException;

public class StandardThreadExecutor implements Executor {
    
    // ---------------------------------------------- Properties
    /**
     * Default thread priority
     */
    protected int threadPriority = Thread.NORM_PRIORITY;

    /**
     * Run threads in daemon or non-daemon state
     */
    protected boolean daemon = true;
    
    /**
     * Default name prefix for the thread name
     */
    protected String namePrefix = "tomcat-exec-";
    
    /**
     * max number of threads
     */
    protected int maxThreads = 200;
    
    /**
     * min number of threads
     */
    protected int minSpareThreads = 25;
    
    /**
     * idle time in milliseconds
     */
    protected int maxIdleTime = 60000;
    
    /**
     * The executor we use for this component
     */
    protected ThreadPoolExecutor executor = null;
    
    /**
     * the name of this thread pool
     */
    protected String name;
    
    /**
     * Number of tasks submitted and not yet completed.
     */
    protected AtomicInteger submittedTasksCount;
    
    /**
     * The maximum number of elements that can queue up before we reject them
     */
    protected int maxQueueSize = Integer.MAX_VALUE;

    private LifecycleSupport lifecycle = new LifecycleSupport(this);
    // ---------------------------------------------- Constructors
    public StandardThreadExecutor() {
        //empty constructor for the digester
    }
    

    
    // ---------------------------------------------- Public Methods
    public void start() throws LifecycleException {
        lifecycle.fireLifecycleEvent(BEFORE_START_EVENT, null);
        TaskQueue taskqueue = new TaskQueue(maxQueueSize);
        TaskThreadFactory tf = new TaskThreadFactory(namePrefix);
        lifecycle.fireLifecycleEvent(START_EVENT, null);
        executor = new ThreadPoolExecutor(getMinSpareThreads(), getMaxThreads(), maxIdleTime, TimeUnit.MILLISECONDS,taskqueue, tf) {
			@Override
			protected void afterExecute(Runnable r, Throwable t) {
				AtomicInteger atomic = submittedTasksCount;
				if(atomic!=null) {
					atomic.decrementAndGet();
				}
			}
        };
        taskqueue.setParent( (ThreadPoolExecutor) executor);
        submittedTasksCount = new AtomicInteger();
        lifecycle.fireLifecycleEvent(AFTER_START_EVENT, null);
    }
    
    public void stop() throws LifecycleException{
        lifecycle.fireLifecycleEvent(BEFORE_STOP_EVENT, null);
        lifecycle.fireLifecycleEvent(STOP_EVENT, null);
        if ( executor != null ) executor.shutdown();
        executor = null;
        submittedTasksCount = null;
        lifecycle.fireLifecycleEvent(AFTER_STOP_EVENT, null);
    }

    // This method is not used by Tomcat 6, but is available in later versions
    public void execute(Runnable command, long timeout, TimeUnit unit) {
        if ( executor != null ) {
            submittedTasksCount.incrementAndGet();
            try {
                executor.execute(command);
            } catch (RejectedExecutionException rx) {
                //there could have been contention around the queue
                try {
                    if ( !( (TaskQueue) executor.getQueue()).force(command,timeout,unit) ) {
                        submittedTasksCount.decrementAndGet();
                        throw new RejectedExecutionException("Work queue full.");
                    }
                }catch (InterruptedException x) {
                    throw new RejectedExecutionException("Interrupted.",x);
                }
            }
        } else throw new IllegalStateException("StandardThreadPool not started.");
    }

    public void execute(Runnable command) {
        if ( executor != null ) {
        	submittedTasksCount.incrementAndGet();
            try {
                executor.execute(command);
            } catch (RejectedExecutionException rx) {
                //there could have been contention around the queue
                if ( !( (TaskQueue) executor.getQueue()).force(command) ) {
                	submittedTasksCount.decrementAndGet();
                	throw new RejectedExecutionException("Work queue full.");
                }
            }
        } else throw new IllegalStateException("StandardThreadPool not started.");
    }

    public int getThreadPriority() {
        return threadPriority;
    }

    public boolean isDaemon() {

        return daemon;
    }

    public String getNamePrefix() {
        return namePrefix;
    }

    public int getMaxIdleTime() {
        return maxIdleTime;
    }

    public int getMaxThreads() {
        return maxThreads;
    }

    public int getMinSpareThreads() {
        return minSpareThreads;
    }

    public String getName() {
        return name;
    }

    public void setThreadPriority(int threadPriority) {
        this.threadPriority = threadPriority;
    }

    public void setDaemon(boolean daemon) {
        this.daemon = daemon;
    }

    public void setNamePrefix(String namePrefix) {
        this.namePrefix = namePrefix;
    }

    public void setMaxIdleTime(int maxIdleTime) {
        this.maxIdleTime = maxIdleTime;
        if (executor != null) {
            executor.setKeepAliveTime(maxIdleTime, TimeUnit.MILLISECONDS);
        }
    }

    public void setMaxThreads(int maxThreads) {
        this.maxThreads = maxThreads;
        if (executor != null) {
            executor.setMaximumPoolSize(maxThreads);
        }
    }

    public void setMinSpareThreads(int minSpareThreads) {
        this.minSpareThreads = minSpareThreads;
        if (executor != null) {
            executor.setCorePoolSize(minSpareThreads);
        }
    }

    public void setName(String name) {
        this.name = name;
    }
    
    public void setMaxQueueSize(int size) {
        this.maxQueueSize = size;
    }

    public int getMaxQueueSize() {
        return maxQueueSize;
    }

    /**
     * Add a LifecycleEvent listener to this component.
     *
     * @param listener The listener to add
     */
    public void addLifecycleListener(LifecycleListener listener) {
        lifecycle.addLifecycleListener(listener);
    }


    /**
     * Get the lifecycle listeners associated with this lifecycle. If this 
     * Lifecycle has no listeners registered, a zero-length array is returned.
     */
    public LifecycleListener[] findLifecycleListeners() {
        return lifecycle.findLifecycleListeners();
    }


    /**
     * Remove a LifecycleEvent listener from this component.
     *
     * @param listener The listener to remove
     */
    public void removeLifecycleListener(LifecycleListener listener) {
        lifecycle.removeLifecycleListener(listener);
    }

    // Statistics from the thread pool
    public int getActiveCount() {
        return (executor != null) ? executor.getActiveCount() : 0;
    }

    public long getCompletedTaskCount() {
        return (executor != null) ? executor.getCompletedTaskCount() : 0;
    }

    public int getCorePoolSize() {
        return (executor != null) ? executor.getCorePoolSize() : 0;
    }

    public int getLargestPoolSize() {
        return (executor != null) ? executor.getLargestPoolSize() : 0;
    }

    public int getPoolSize() {
        return (executor != null) ? executor.getPoolSize() : 0;
    }

    public int getQueueSize() {
        return (executor != null) ? executor.getQueue().size() : -1;
    }

    // ---------------------------------------------- TaskQueue Inner Class
    class TaskQueue extends LinkedBlockingQueue<Runnable> {
        ThreadPoolExecutor parent = null;

        public TaskQueue() {
            super();
        }

        public TaskQueue(int capacity) {
            super(capacity);
        }

        public TaskQueue(Collection<? extends Runnable> c) {
            super(c);
        }

        public void setParent(ThreadPoolExecutor tp) {
            parent = tp;
        }
        
        public boolean force(Runnable o) {
            if ( parent.isShutdown() ) throw new RejectedExecutionException("Executor not running, can't force a command into the queue");
            return super.offer(o); //forces the item onto the queue, to be used if the task is rejected
        }

        public boolean force(Runnable o, long timeout, TimeUnit unit) throws InterruptedException {
            if ( parent.isShutdown() ) throw new RejectedExecutionException("Executor not running, can't force a command into the queue");
            return super.offer(o,timeout,unit); //forces the item onto the queue, to be used if the task is rejected
        }

        public boolean offer(Runnable o) {
            //we can't do any checks
            if (parent==null) return super.offer(o);
            int poolSize = parent.getPoolSize();
            //we are maxed out on threads, simply queue the object
            if (parent.getPoolSize() == parent.getMaximumPoolSize()) return super.offer(o);
            //we have idle threads, just add it to the queue
            //note that we don't use getActiveCount(), see BZ 49730
			AtomicInteger submittedTasksCount = StandardThreadExecutor.this.submittedTasksCount;
			if(submittedTasksCount!=null) {
				if (submittedTasksCount.get()<=poolSize) return super.offer(o);
			}
            //if we have less threads than maximum force creation of a new thread
            if (poolSize<parent.getMaximumPoolSize()) return false;
            //if we reached here, we need to add it to the queue
            return super.offer(o);
        }
    }

    // ---------------------------------------------- ThreadFactory Inner Class
    class TaskThreadFactory implements ThreadFactory {
        final ThreadGroup group;
        final AtomicInteger threadNumber = new AtomicInteger(1);
        final String namePrefix;

        TaskThreadFactory(String namePrefix) {
            SecurityManager s = System.getSecurityManager();
            group = (s != null) ? s.getThreadGroup() : Thread.currentThread().getThreadGroup();
            this.namePrefix = namePrefix;
        }

        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r, namePrefix + threadNumber.getAndIncrement());
            t.setDaemon(daemon);
            t.setPriority(getThreadPriority());
            return t;
        }
    }


}
