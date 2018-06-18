/*
 * Copyright (C) 2005-2008 Jive Software. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.plugin;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.mina.core.filterchain.DefaultIoFilterChainBuilder;
import org.apache.mina.core.filterchain.IoFilter;
import org.apache.mina.transport.socket.SocketAcceptor;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.container.PluginManagerListener;
import org.jivesoftware.openfire.spi.ConnectionManagerImpl;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.PropertyEventDispatcher;
import org.jivesoftware.util.PropertyEventListener;

import static org.jivesoftware.openfire.spi.ConnectionManagerImpl.COMPRESSION_FILTER_NAME;
import static org.jivesoftware.openfire.spi.ConnectionManagerImpl.TLS_FILTER_NAME;

/**
 * Debugger plugin that prints XML traffic to stdout. By default it will only print
 * raw XML traffic (by using a MINA filter). To turn on printing of interpreted XML
 * (i.e. parsed XML) just enable the system property <tt>plugin.debugger.interpretedAllowed</tt>.
 * There is no need to restart the plugin or the server.
 *
 * @author Gaston Dombiak
 */
public class DebuggerPlugin implements Plugin, PropertyEventListener {

    private static final Logger LOGGER = LogManager.getLogger();

    static final String PROPERTY_PREFIX = "plugin.xmldebugger.";
    private static final String PROPERTY_LOG_TO_STDOUT_ENABLED = PROPERTY_PREFIX + "logToStdOut";
    private static final String PROPERTY_LOG_TO_FILE_ENABLED = PROPERTY_PREFIX + "logToFile";


    private final RawPrintFilter defaultPortFilter;
    private final RawPrintFilter oldPortFilter;
    private final RawPrintFilter componentPortFilter;
    private final RawPrintFilter multiplexerPortFilter;
    private final Set<RawPrintFilter> rawPrintFilters;
    private final InterpretedXMLPrinter interpretedPrinter;
    private boolean loggingToStdOut;
    private boolean loggingToFile;

    public DebuggerPlugin() {
        loggingToStdOut = JiveGlobals.getBooleanProperty(PROPERTY_LOG_TO_STDOUT_ENABLED, true);
        loggingToFile = JiveGlobals.getBooleanProperty(PROPERTY_LOG_TO_FILE_ENABLED, false);
        defaultPortFilter = new RawPrintFilter(this, "C2S");
        oldPortFilter = new RawPrintFilter(this, "SSL");
        componentPortFilter = new RawPrintFilter(this, "ExComp");
        multiplexerPortFilter = new RawPrintFilter(this, "CM");
        rawPrintFilters = new HashSet<>(Arrays.asList(defaultPortFilter, oldPortFilter, componentPortFilter, multiplexerPortFilter));
        interpretedPrinter = new InterpretedXMLPrinter(this);
    }

    public void initializePlugin(final PluginManager pluginManager, final File pluginDirectory) {
        if (pluginManager.isExecuted()) {
            addInterceptors();
        } else {
            pluginManager.addPluginManagerListener(new PluginManagerListener() {
                public void pluginsMonitored() {
                    // Stop listening for plugin events
                    pluginManager.removePluginManagerListener(this);
                    // Start listeners
                    addInterceptors();
                }
            });
        }
    }

    private void addFilterToChain(final SocketAcceptor acceptor, final IoFilter filter) {
        if (acceptor == null) {
            LOGGER.debug("Not adding filter '{}' to acceptor that is null.", RawPrintFilter.FILTER_NAME);
            return;
        }

        final DefaultIoFilterChainBuilder chain = acceptor.getFilterChain();
        if (chain.contains(COMPRESSION_FILTER_NAME)) {
            LOGGER.debug("Adding filter '{}' as the first filter after the compression filter in acceptor {}", RawPrintFilter.FILTER_NAME, acceptor);
            chain.addAfter(COMPRESSION_FILTER_NAME, RawPrintFilter.FILTER_NAME, filter);
        } else if (chain.contains(TLS_FILTER_NAME)) {
            LOGGER.debug("Adding filter '{}' as the first filter after the TLS filter in acceptor {}", RawPrintFilter.FILTER_NAME, acceptor);
            chain.addAfter(TLS_FILTER_NAME, RawPrintFilter.FILTER_NAME, filter);
        } else {
            LOGGER.debug("Adding filter '{}' as the last filter in acceptor {}", RawPrintFilter.FILTER_NAME, acceptor);
            chain.addLast(RawPrintFilter.FILTER_NAME, filter);
        }
    }

    private void removeFilterFromChain(final SocketAcceptor acceptor) {
        if (acceptor == null) {
            LOGGER.debug("Not removing filter '{}' from acceptor that is null.", RawPrintFilter.FILTER_NAME);
            return;
        }

        if (acceptor.getFilterChain().contains(RawPrintFilter.FILTER_NAME)) {
            LOGGER.debug("Removing filter '{}' from acceptor {}", RawPrintFilter.FILTER_NAME, acceptor);
            acceptor.getFilterChain().remove(RawPrintFilter.FILTER_NAME);
        } else {
            LOGGER.debug("Unable to remove non-existing filter '{}' from acceptor {}", RawPrintFilter.FILTER_NAME, acceptor);
        }
    }

    private void addInterceptors() {
        // Add filter to filter chain builder
        final ConnectionManagerImpl connManager = (ConnectionManagerImpl) XMPPServer.getInstance().getConnectionManager();

        addFilterToChain(connManager.getSocketAcceptor(), defaultPortFilter);
        addFilterToChain(connManager.getSSLSocketAcceptor(), oldPortFilter);
        addFilterToChain(connManager.getComponentAcceptor(), componentPortFilter);
        addFilterToChain(connManager.getMultiplexerSocketAcceptor(), multiplexerPortFilter);

        interpretedPrinter.wasEnabled(interpretedPrinter.isEnabled());

        // Listen to property events
        PropertyEventDispatcher.addListener(this);
        LOGGER.debug("Plugin initialisation complete");
    }

    public void destroyPlugin() {
        // Stop listening to property events
        PropertyEventDispatcher.removeListener(this);
        // Remove filter from filter chain builder
        ConnectionManagerImpl connManager = (ConnectionManagerImpl) XMPPServer.getInstance().getConnectionManager();
        removeFilterFromChain(connManager.getSocketAcceptor());
        removeFilterFromChain(connManager.getSSLSocketAcceptor());
        removeFilterFromChain(connManager.getComponentAcceptor());
        removeFilterFromChain(connManager.getMultiplexerSocketAcceptor());

        // Remove the filters from existing sessions
        defaultPortFilter.shutdown();
        oldPortFilter.shutdown();
        componentPortFilter.shutdown();
        multiplexerPortFilter.shutdown();

        // Remove the packet interceptor that prints interpreted XML
        interpretedPrinter.wasEnabled(false);

        LOGGER.debug("Plugin destruction complete");
    }

    public RawPrintFilter getDefaultPortFilter() {
        return defaultPortFilter;
    }

    public RawPrintFilter getOldPortFilter() {
        return oldPortFilter;
    }

    public RawPrintFilter getComponentPortFilter() {
        return componentPortFilter;
    }

    public RawPrintFilter getMultiplexerPortFilter() {
        return multiplexerPortFilter;
    }

    public InterpretedXMLPrinter getInterpretedPrinter() {
        return interpretedPrinter;
    }

    public void propertySet(String property, Map<String, Object> params) {
        final boolean enabled = Boolean.parseBoolean(String.valueOf(params.get("value")));
        enableOrDisableLogger(property, enabled);
    }

    public void propertyDeleted(String property, Map<String, Object> params) {
        enableOrDisableLogger(property, false);
    }

    private void enableOrDisableLogger(final String property, final boolean enabled) {
        switch (property) {
            case InterpretedXMLPrinter.PROPERTY_ENABLED:
                interpretedPrinter.wasEnabled(enabled);
                break;
            case PROPERTY_LOG_TO_STDOUT_ENABLED:
                loggingToStdOut = enabled;
                LOGGER.debug("STDOUT logger {}", enabled ? "enabled" : "disabled");
                break;
            case PROPERTY_LOG_TO_FILE_ENABLED:
                loggingToFile = enabled;
                LOGGER.debug("file logger {}", enabled ? "enabled" : "disabled");
                break;
            default:
                // Is it one of the RawPrintFilters?
                for (final RawPrintFilter filter : rawPrintFilters) {
                    if(filter.getPropertyName().equals(property)) {
                        filter.wasEnabled(enabled);
                        break;
                    }
                }
        }
    }

    public void xmlPropertySet(String property, Map<String, Object> params) {
        // Do nothing
    }

    public void xmlPropertyDeleted(String property, Map<String, Object> params) {
        // Do nothing
    }

    public boolean isLoggingToStdOut() {
        return loggingToStdOut;
    }

    public void setLoggingToStdOut(final boolean enabled) {
        JiveGlobals.setProperty(PROPERTY_LOG_TO_STDOUT_ENABLED, String.valueOf(enabled));
    }

    public boolean isLoggingToFile() {
        return loggingToFile;
    }

    public void setLoggingToFile(final boolean enabled) {
        JiveGlobals.setProperty(PROPERTY_LOG_TO_FILE_ENABLED, String.valueOf(enabled));
    }

    void log(final String messageToLog) {
        if (loggingToStdOut) {
            System.out.println(messageToLog);
        }
        if (loggingToFile) {
            LOGGER.debug(messageToLog);
        }
    }
}
