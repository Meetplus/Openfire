package org.jivesoftware.openfire.spi;

import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.jivesoftware.openfire.Connection;
import org.jivesoftware.openfire.ServerPort;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.keystore.CertificateStore;
import org.jivesoftware.openfire.keystore.CertificateStoreConfiguration;
import org.jivesoftware.openfire.keystore.CertificateStoreManager;
import org.jivesoftware.openfire.net.SocketConnection;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * As a server, Openfire accepts connection requests from other network entities. The exact functionality is subject to
 * configuration details (eg: TCP port on which connections are accepted, TLS policy that is applied, etc). An instance
 * of this class is used to manage this configuration for one type of connection (on one TCP port), and is responsible
 * for managing the lifecycle of the entity that implements the acceptance of new socket connections (as implemented by
 * {@link ConnectionAcceptor}.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
// TODO most getters in this class assume that the ConnectionAcceptor property value match the property values of JiveGlobals. This should be the case, but should be asserted.
public class ConnectionListener
{
    private Logger Log;

    // Connection characteristics
    private final ConnectionType type;
    private final int defaultPort;
    private final InetAddress bindAddress; // if null, represents any local address (typically 0.0.0.0 or ::0)
    private CertificateStoreConfiguration identityStoreConfiguration;
    private CertificateStoreConfiguration trustStoreConfiguration;

    // Name of properties used to configure the acceptor.
    private final String tcpPortPropertyName;
    private final String isEnabledPropertyName;
    private final String maxPoolSizePropertyName; // Max threads
    private final String maxReadBufferPropertyName; // Max buffer size
    private final String tlsPolicyPropertyName;
    private final String clientAuthPolicyPropertyName;

    // The entity that performs the acceptance of new (socket) connections.
    private ConnectionAcceptor connectionAcceptor;


    ConnectionListener getConnectionListener( ConnectionType type ) {
        ConnectionManagerImpl connectionManager = ((ConnectionManagerImpl) XMPPServer.getInstance().getConnectionManager());
        try
        {
            return connectionManager.getListener( type, getTLSPolicy().equals( Connection.TLSPolicy.legacyMode ) );
        } catch ( RuntimeException ex ) {
            // TODO This entire catch-block is a hack, and should be removed. Listeners for all types should be available (but pending implementation of some, this hack was added).
            Log.warn( "A connection listener for '{}' is not available. Using fallback: '{}'.", type, type.getFallback() );
            return getConnectionListener( type.getFallback() );
        }
    }

    /**
     * Instantiates a new connection listener.
     */
    public ConnectionListener( ConnectionType type, String tcpPortPropertyName, int defaultPort, String isEnabledPropertyName, String maxPoolSizePropertyName, String maxReadBufferPropertyName, String tlsPolicyPropertyName, String clientAuthPolicyPropertyName, InetAddress bindAddress, CertificateStoreConfiguration identityStoreConfiguration, CertificateStoreConfiguration trustStoreConfiguration )
    {
        this.type = type;
        this.tcpPortPropertyName = tcpPortPropertyName;
        this.defaultPort = defaultPort;
        this.isEnabledPropertyName = isEnabledPropertyName;
        this.maxPoolSizePropertyName = maxPoolSizePropertyName;
        this.maxReadBufferPropertyName = maxReadBufferPropertyName;
        this.tlsPolicyPropertyName = tlsPolicyPropertyName;
        this.clientAuthPolicyPropertyName = clientAuthPolicyPropertyName;
        this.bindAddress = bindAddress;
        this.identityStoreConfiguration = identityStoreConfiguration;
        this.trustStoreConfiguration = trustStoreConfiguration;

        // A listener cannot be changed into or from legacy mode. That fact is safe to use in the name of the logger..
        final String name = getType().toString().toLowerCase() + ( getTLSPolicy().equals( Connection.TLSPolicy.legacyMode ) ? "-legacyMode" : "" );
        this.Log = LoggerFactory.getLogger( ConnectionListener.class.getName() + "[" + name + "]" );
    }

    /**
     * Return if the configuration allows this listener to be enabled (but does not verify that the listener is
     * indeed active).
     *
     * @return true if configuration allows this listener to be enabled, otherwise false.
     */
    public boolean isEnabled()
    {
        // TODO if this is an SSL connection, legacy code required the existence of at least one certificate in the identity store in addition to the property value (although no such requirement is enforced for a TLS connection that might or might not be elevated to encrypted).
        return JiveGlobals.getBooleanProperty( isEnabledPropertyName, true );
    }

    /**
     * Activates or deactivates the listener, and changes the configuration accordingly. This configuration change is
     * persisted. An invocation of this method has no effect if the listener is already in the provided state.
     */
    public synchronized void enable( boolean enable )
    {
        final boolean isRunning = connectionAcceptor != null;
        if ( enable == isRunning )
        {
            // This is likely to be caused by a cadence of property changes and harmless / safe to ignore.
            Log.debug( "Ignoring enable({}): listener already in this state.", enable );
            return;
        }

        JiveGlobals.setProperty( isEnabledPropertyName, Boolean.toString( enable ) );
        if ( isRunning )
        {
            start();
        }
        else
        {
            stop();
        }
    }

    /**
     * Attempts to start the connection acceptor, creating a new instance when needed.
     *
     * An invocation of this method does not change the configuration for this connection. As a result, an acceptor will
     * <em>not</em> be started when the listener is not enabled (in such cases, an invocation of this method has no
     * effect).
     *
     * In order to start this listener and persist this as the desired state for this connection, use #enable(true).
     *
     * This method should not be called when an acceptor has already been started (instead, {@link #restart()} should be
     * used to explicitly define the need to stop a previous connection). The current implementation of this method will
     * stop a pre-existing acceptor, but only when it is currently not serving connections. When the acceptor is not
     * idle, this method has no effect. This behavior might change in the future.
     */
    public synchronized void start()
    {
        if ( !isEnabled() )
        {
            Log.debug( "Not starting: disabled by configuration." );
            return;
        }

        if ( connectionAcceptor != null )
        {
            // This might indicate an illegal state. Legacy code allows for this, so we won't throw a runtime exception (for now).
            if ( !connectionAcceptor.isIdle() )
            {
                Log.warn( "Unable to start: it appears to have already been started (and it is currently serving connections)! To restart, first stop this listener explicitly." );
                return;
            }
            else
            {
                Log.warn( "Stopping (in order to restart) an instance that has already been started, but is idle. This start would have failed if the listener was not idle. The implementation should have called stop() or restart() first, to ensure a clean restart!" );
                connectionAcceptor.stop();
            }
        }

        Log.debug( "Starting..." );
        connectionAcceptor = new ConnectionAcceptor( generateConnectionConfiguration() );
        connectionAcceptor.start();
        Log.info( "Started." );
    }

    /**
     * Generates an immutable ConnectionConfiguration based on the current state.
     *
     * @return an immutable configuration, never null.
     */
    public ConnectionConfiguration generateConnectionConfiguration()
    {
        final int maxThreadPoolSize = JiveGlobals.getIntProperty( maxPoolSizePropertyName, 16 );

        final int maxBufferSize;
        if ( maxReadBufferPropertyName != null )
        {
            maxBufferSize = JiveGlobals.getIntProperty( maxReadBufferPropertyName, 10 * 1024 * 1024 );
        }
        else
        {
            maxBufferSize = -1; // No upper bound. Should be used for high-volume & trusted connections only (if at all).
        }

        Connection.ClientAuth clientAuth;
        if ( clientAuthPolicyPropertyName == null )
        {
            clientAuth = Connection.ClientAuth.wanted;
        }
        else
        {
            try
            {
                final String value = JiveGlobals.getProperty( clientAuthPolicyPropertyName, Connection.ClientAuth.wanted.name() );
                clientAuth = Connection.ClientAuth.valueOf( value );
            }
            catch ( IllegalArgumentException e )
            {
                Log.warn( "Invalid client auth value. A default will be used.", e );
                clientAuth = Connection.ClientAuth.wanted;
            }
        }

        // Take the current state of this instance, and create a new configuration.
        return new ConnectionConfiguration(
                getType(),
                maxThreadPoolSize,
                maxBufferSize,
                clientAuth,
                getBindAddress(),
                getPort(),
                getTLSPolicy(),
                identityStoreConfiguration,
                trustStoreConfiguration,
                acceptSelfSignedCertificates(),
                verifyCertificateValidity(),
                getEncryptionProtocolsEnabled(),
                getEncryptionProtocolsDisabled(),
                getCipherSuitesEnabled(),
                getCipherSuitesDisabled()
        );
    }

    /**
     * Attempts to stop the connection acceptor. If the connection acceptor has not been started, an invocation of this
     * method has no effect.
     *
     * An invocation of this method does not change the configuration for this connection. As a result, the acceptor for
     * this connection can be restarted when this ConnectionListener instance is replaced.
     *
     * In order to stop this listener (and persist this as the desired state for this connection, use #enable(false).
     */
    protected synchronized void stop()
    {
        if ( connectionAcceptor == null )
        {
            Log.debug( "Not stopping: it hasn't been started." );
            return;
        }

        Log.debug( "Stopping..." );
        try
        {
            connectionAcceptor.stop();
        }
        finally
        {
            connectionAcceptor = null;
        }
        Log.info( "Stopped." );
    }

    /**
     * Starts or restarts this instance (typically used to put into effect a configuration change).
     *
     * A connection that was started, but is disabled by configuration will be stopped but not restarted by an
     * invocation of this method.
     */
    public synchronized void restart()
    {
        Log.debug( "Restarting..." );
        try
        {
            if ( connectionAcceptor != null )
            {
                stop();
            }
        }
        finally
        {
            start(); // won't actually start anything if not enabled.
        }
        Log.debug( "Done restarting..." );
    }

    /**
     * Returns the acceptor that is managed by the instance.
     *
     * @return A socket acceptor, or null when this listener is disabled.
     */
    // TODO see if we can avoid exposing MINA internals.
    public NioSocketAcceptor getSocketAcceptor()
    {
        if ( connectionAcceptor == null )
        {
            return null;
        }

        return connectionAcceptor.getSocketAcceptor();
    }

    /**
     * Returns the network address on which connections are accepted when this listener is enabled.
     *
     * This method can return null, which indicates that connections are accepted on any local address (typically
     * 0.0.0.0 or ::0).
     *
     * @return A network address or null.
     */
    public InetAddress getBindAddress()
    {
        return bindAddress;
    }

    /**
     * Returns the type of connection that is accepted by this listener.
     *
     * @return A connection type (never null).
     */
    public ConnectionType getType()
    {
        return type;
    }


    /**
     * The TCP port number on which connections will be accepted when this listener is enabled.
     *
     * @return A port number.
     */
    public int getPort()
    {
        if ( tcpPortPropertyName != null )
        {
            return JiveGlobals.getIntProperty( tcpPortPropertyName, defaultPort );
        }
        else
        {
            return defaultPort;
        }
    }

    /**
     * Changes the TCP port on which connections are accepted, This configuration change is persisted.
     *
     * If the listener is currently enabled, this configuration change will be applied immediately (which will cause a
     * restart of the underlying connection acceptor).
     *
     * An invocation of this method has no effect if the new port value is equal to the existing value.
     *
     * @param port A port number.
     */
    public void setPort( int port )
    {
        final long oldPort = getPort();
        if (port == oldPort ) {
            Log.debug( "Ignoring port change request (to '{}'): listener already in this state.", port );
            return;
        }

        Log.debug( "Changing port from '{}' to '{}'.", oldPort, port );
        if ( tcpPortPropertyName != null )
        {
            JiveGlobals.setProperty( tcpPortPropertyName, String.valueOf( port ) );
        }
        restart();
    }

    /**
     * Returns whether TLS is mandatory, optional, disabled or mandatory immediately for new connections. When TLS is
     * mandatory connections are required to be encrypted or otherwise will be closed.
     *
     * When TLS is disabled connections are not allowed to be (or become) encrypted. In this case, connections will be
     * closed when encryption is attempted.
     *
     * @return An encryption policy, never null.
     */
    public Connection.TLSPolicy getTLSPolicy()
    {
        if ( tlsPolicyPropertyName.equals( Connection.TLSPolicy.legacyMode.name() ) )
        {
            return Connection.TLSPolicy.legacyMode;
        }

        final String policyName = JiveGlobals.getProperty( tlsPolicyPropertyName, Connection.TLSPolicy.optional.toString() );
        Connection.TLSPolicy tlsPolicy;
        try
        {
            tlsPolicy = Connection.TLSPolicy.valueOf(policyName);
        }
        catch ( IllegalArgumentException e )
        {
            Log.error( "Error parsing property value of '{}' into a valid TLS_POLICY. Offending value: '{}'.", policyName, tlsPolicyPropertyName, e );
            tlsPolicy = Connection.TLSPolicy.optional;
        }
        return tlsPolicy;
    }

    /**
     * Sets whether TLS is mandatory, optional, disabled or mandatory immediately for new connections. When TLS is
     * mandatory connections are required to be encrypted or otherwise will be closed. This configuration change is
     * persisted.
     *
     * If the listener is currently enabled, this configuration change will be applied immediately (which will cause a
     * restart of the underlying connection acceptor).
     *
     * When TLS is disabled connections are not allowed to be (or become) encrypted. In this case, connections will be
     * closed when encryption is attempted.
     *
     * This method disallows changing the policy from or into legacy mode. Such a change is logged but otherwise
     * ignored.
     *
     * An invocation of this method has no effect if the new policy value is equal to the existing value.
     *
     * @param policy an encryption policy (not null).
     */
    public void setTLSPolicy( SocketConnection.TLSPolicy policy )
    {
        final Connection.TLSPolicy oldPolicy = getTLSPolicy();
        if ( oldPolicy.equals( policy ) )
        {
            Log.debug( "Ignoring TLS Policy change request (to '{}'): listener already in this state.", policy );
            return;
        }

        if ( Connection.TLSPolicy.legacyMode.equals( policy ) )
        {
            Log.warn( "Ignoring TLS Policy change request (to '{}'): You cannot reconfigure an existing connection (from '{}') into legacy mode!", policy, oldPolicy );
            return;
        }

        if ( Connection.TLSPolicy.legacyMode.equals( oldPolicy ) )
        {
            Log.warn( "Ignoring TLS Policy change request (to '{}'): You cannot reconfigure an existing connection that is in legacy mode!", policy );
            return;
        }

        Log.debug( "Changing TLS Policy from '{}' to '{}'.", oldPolicy, policy );
        JiveGlobals.setProperty( tlsPolicyPropertyName, policy.toString() );
        restart();
    }

    /**
     * Returns the configuration for the identity store that identifies this instance of Openfire to the peer
     * on connections created by this listener.
     *
     * @return The configuration of the identity store (not null)
     */
    public CertificateStoreConfiguration getIdentityStoreConfiguration() {
        return this.identityStoreConfiguration;
    }

    /**
     * Replaces the configuration for the identity store that identifies this instance of Openfire to the peer
     * on connections created by this listener.
     *
     * If the listener is currently enabled, this configuration change will be applied immediately (which will cause a
     * restart of the underlying connection acceptor).
     *
     * @param configuration The identity store configuration (not null)
     */
    public void setIdentityStoreConfiguration( CertificateStoreConfiguration configuration )
    {
        if ( this.identityStoreConfiguration.equals( configuration ) )
        {
            Log.debug( "Ignoring identity store configuration change request (to '{}'): listener already in this state.", configuration );
            return;
        }
        Log.debug( "Changing identity store configuration  from '{}' to '{}'.", this.identityStoreConfiguration, configuration );
        this.identityStoreConfiguration = configuration;
        restart();
    }

    /**
     * Returns the configuration for the trust store that is used to identify/trust peers on connections created by this
     * listener.
     *
     * @return The configuration of the identity store (not null)
     */
    public CertificateStoreConfiguration getTrustStoreConfiguration() {
        return this.trustStoreConfiguration;
    }

    /**
     * Replaces the configuration for the trust store that is used to identify/trust peers on connections created by
     * this listener.
     *
     * If the listener is currently enabled, this configuration change will be applied immediately (which will cause a
     * restart of the underlying connection acceptor).
     *
     * @return The configuration of the identity store (not null)
     */
    public void setTrustStoreConfiguration( CertificateStoreConfiguration configuration )
    {
        if ( this.trustStoreConfiguration.equals( configuration ) )
        {
            Log.debug( "Ignoring trust store configuration change request (to '{}'): listener already in this state.", configuration );
            return;
        }
        Log.debug( "Changing trust store configuration  from '{}' to '{}'.", this.trustStoreConfiguration, configuration );
        this.trustStoreConfiguration = configuration;
        restart();
    }

//    /**
//     * The KeyStore type (jks, jceks, pkcs12, etc) for the identity and trust store for connections created by this
//     * listener.
//     *
//     * @return a store type (never null).
//     * @see <a href="https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyStore">Java Cryptography Architecture Standard Algorithm Name Documentation</a>
//     */
//    public String getKeyStoreType()
//    {
//        final String propertyName = type.getPrefix() + "storeType";
//        final String defaultValue = "jks";
//
//        if ( type.getFallback() == null )
//        {
//            return JiveGlobals.getProperty( propertyName, defaultValue ).trim();
//        }
//        else
//        {
//            return JiveGlobals.getProperty( propertyName, getConnectionListener( type.getFallback() ).getKeyStoreType() ).trim();
//        }
//    }
//
//    public void setKeyStoreType( String keyStoreType )
//    {
//        // Always set the property explicitly even if it appears the equal to the old value (the old value might be a fallback value).
//        JiveGlobals.setProperty( type.getPrefix() + "storeType", keyStoreType );
//
//        final String oldKeyStoreType = getKeyStoreType();
//        if ( oldKeyStoreType.equals( keyStoreType ) )
//        {
//            Log.debug( "Ignoring KeyStore type change request (to '{}'): listener already in this state.", keyStoreType );
//            return;
//        }
//
//        Log.debug( "Changing KeyStore type from '{}' to '{}'.", oldKeyStoreType, keyStoreType );
//        restart();
//    }
//
//    /**
//     * The password of the identity store for connection created by this listener.
//     *
//     * @return a password (never null).
//     */
//    public String getIdentityStorePassword()
//    {
//        final String propertyName = type.getPrefix() + "keypass";
//        final String defaultValue = "changeit";
//
//        if ( type.getFallback() == null )
//        {
//            return JiveGlobals.getProperty( propertyName, defaultValue ).trim();
//        }
//        else
//        {
//            return JiveGlobals.getProperty( propertyName, getConnectionListener( type.getFallback() ).getIdentityStorePassword() ).trim();
//        }
//    }
//
//    public void setIdentityStorePassword( String password )
//    {
//        // Always set the property explicitly even if it appears the equal to the old value (the old value might be a fallback value).
//        JiveGlobals.setProperty( type.getPrefix() + "keypass", password );
//
//        final String oldPassword = getIdentityStorePassword();
//        if ( oldPassword.equals( password ) )
//        {
//            Log.debug( "Ignoring identity store password change request: listener already in this state." ); // Do not put passwords in a logfile.
//            return;
//        }
//
//        Log.debug( "Changing identity store password." ); // Do not put passwords in a logfile.
//        restart();
//    }
//
//    /**
//     * The password of the trust store for connections created by this listener.
//     *
//     * @return a password (never null).
//     */
//    public String getTrustStorePassword()
//    {
//        final String propertyName = type.getPrefix() + "trustpass";
//        final String defaultValue = "changeit";
//
//        if ( type.getFallback() == null )
//        {
//            return JiveGlobals.getProperty( propertyName, defaultValue ).trim();
//        }
//        else
//        {
//            return JiveGlobals.getProperty( propertyName, getConnectionListener( type.getFallback() ).getTrustStorePassword() ).trim();
//        }
//    }
//
//    public void setTrustStorePassword( String password )
//    {
//        // Always set the property explicitly even if it appears the equal to the old value (the old value might be a fallback value).
//        JiveGlobals.setProperty( type.getPrefix() + "trustpass", password );
//
//        final String oldPassword = getTrustStorePassword();
//        if ( oldPassword.equals( password ) )
//        {
//            Log.debug( "Ignoring trust store password change request: listener already in this state." ); // Do not put passwords in a logfile.
//            return;
//        }
//
//        Log.debug( "Changing trust store password." ); // Do not put passwords in a logfile.
//        restart();
//    }
//
//    /**
//     * The location (relative to OPENFIRE_HOME) of the identity store for connections created by this listener.
//     *
//     * @return a path (never null).
//     */
//    public String getIdentityStoreLocation()
//    {
//        final String propertyName = type.getPrefix()  + "keystore";
//        final String defaultValue = "resources" + File.separator + "security" + File.separator + "keystore";
//
//        if ( type.getFallback() == null )
//        {
//            return JiveGlobals.getProperty( propertyName, defaultValue ).trim();
//        }
//        else
//        {
//            return JiveGlobals.getProperty( propertyName, getConnectionListener( type.getFallback() ).getIdentityStoreLocation() ).trim();
//        }
//    }
//
//    public void setIdentityStoreLocation( String location )
//    {
//        // Always set the property explicitly even if it appears the equal to the old value (the old value might be a fallback value).
//        JiveGlobals.setProperty( type.getPrefix() + "keystore", location );
//
//        final String oldLocation = getIdentityStoreLocation();
//        if ( oldLocation.equals( location ) )
//        {
//            Log.debug( "Ignoring identity store location change request (to '{}'): listener already in this state.", location );
//            return;
//        }
//
//        Log.debug( "Changing identity store location from '{}' to '{}'.", oldLocation, location );
//        restart();
//    }
//
//    /**
//     * The location (relative to OPENFIRE_HOME) of the trust store for connections created by this listener.
//     *
//     * @return a path (never null).
//     */
//    public String getTrustStoreLocation()
//    {
//        final String propertyName = type.getPrefix()  + "truststore";
//        final String defaultValue = "resources" + File.separator + "security" + File.separator + "truststore";
//
//        if ( type.getFallback() == null )
//        {
//            return JiveGlobals.getProperty( propertyName, defaultValue ).trim();
//        }
//        else
//        {
//            return JiveGlobals.getProperty( propertyName, getConnectionListener( type.getFallback() ).getTrustStoreLocation() ).trim();
//        }
//    }
//
//    public void setTrustStoreLocation( String location )
//    {
//        // Always set the property explicitly even if it appears the equal to the old value (the old value might be a fallback value).
//        JiveGlobals.setProperty( type.getPrefix() + "truststore", location );
//
//        final String oldLocation = getTrustStoreLocation();
//        if ( oldLocation.equals( location ) )
//        {
//            Log.debug( "Ignoring trust store location change request (to '{}'): listener already in this state.", location );
//            return;
//        }
//
//        Log.debug( "Changing trust store location from '{}' to '{}'.", oldLocation, location );
//        restart();
//    }

    /**
     * A boolean that indicates if self-signed peer certificates can be used to establish an encrypted connection.
     *
     * @return true when self-signed certificates are accepted, otherwise false.
     */
    // TODO add setter!
    public boolean acceptSelfSignedCertificates()
    {
        // TODO these are new properties! Deprecate (migrate?) all existing 'accept-selfsigned properties' (Eg: org.jivesoftware.openfire.session.ConnectionSettings.Server.TLS_ACCEPT_SELFSIGNED_CERTS )
        final String propertyName = type.getPrefix() + "certificate.accept-selfsigned";
        final boolean defaultValue = false;

        if ( type.getFallback() == null )
        {
            return JiveGlobals.getBooleanProperty( propertyName, defaultValue );
        }
        else
        {
            return JiveGlobals.getBooleanProperty( propertyName, getConnectionListener( type.getFallback() ).acceptSelfSignedCertificates() );
        }
    }

    /**
     * A boolean that indicates if the current validity of certificates (based on their 'notBefore' and 'notAfter'
     * property values) is used when they are used to establish an encrypted connection..
     *
     * @return true when certificates are required to be valid to establish a secured connection, otherwise false.
     */
    // TODO add setter!
    public boolean verifyCertificateValidity()
    {
        // TODO these are new properties! Deprecate (migrate?) all existing 'verify / verify-validity properties' (Eg: org.jivesoftware.openfire.session.ConnectionSettings.Server.TLS_CERTIFICATE_VERIFY_VALIDITY )
        final String propertyName = type.getPrefix() + "certificate.verify.validity";
        final boolean defaultValue = true;

        if ( type.getFallback() == null )
        {
            return JiveGlobals.getBooleanProperty( propertyName, defaultValue );
        }
        else
        {
            return JiveGlobals.getBooleanProperty( propertyName, getConnectionListener( type.getFallback() ).acceptSelfSignedCertificates() );
        }
    }

    /**
     * A collection of protocol names that can be used for encryption of connections.
     *
     * When non-empty, the list is intended to specify those protocols (from a larger collection of implementation-
     * supported protocols) that can be used to establish encryption.
     *
     * Values returned by {@link #getEncryptionProtocolsDisabled()} are not included in the result of this method.
     *
     * The order over which values are iterated in the result is equal to the order of values in the comma-separated
     * configuration string. This can, but is not guaranteed to, indicate preference.
     *
     * @return An (ordered) set of protocols, never null but possibly empty.
     */
    // TODO add setter!
    public Set<String> getEncryptionProtocolsEnabled()
    {
        final Set<String> result = new LinkedHashSet<>();
        final String csv = getEncryptionProtocolsEnabledCommaSeparated();
        result.addAll( Arrays.asList( csv.split( "\\s*,\\s*" ) ) );
        result.removeAll( getEncryptionProtocolsDisabled() );
        return result;
    }

    protected String getEncryptionProtocolsEnabledCommaSeparated()
    {
        final String propertyName = type.getPrefix() + "protocols.enabled";
        final String defaultValue = "TLSv1,TLSv1.1,TLSv1.2";

        if ( type.getFallback() == null )
        {
            return JiveGlobals.getProperty( propertyName, defaultValue ).trim();
        }
        else
        {
            return JiveGlobals.getProperty( propertyName, getConnectionListener( type.getFallback() ).getEncryptionProtocolsEnabledCommaSeparated() ).trim();
        }
    }

    /**
     * A collection of protocols that must not be used for encryption of connections.
     *
     * When non-empty, the list is intended to specify those protocols (from a larger collection of implementation-
     * supported protocols) that must not be used to establish encryption.
     *
     * The order over which values are iterated in the result is equal to the order of values in the comma-separated
     * configuration string.
     *
     * @return An (ordered) set of protocols, never null but possibly empty.
     */
    // TODO add setter!
    public Set<String> getEncryptionProtocolsDisabled()
    {
        final Set<String> result = new LinkedHashSet<>();
        final String csv = getEncryptionProtocolsDisabledCommaSeparated();
        result.addAll( Arrays.asList( csv.split( "\\s*,\\s*" ) ) );
        return result;
    }

    protected String getEncryptionProtocolsDisabledCommaSeparated()
    {
        final String propertyName = type.getPrefix() + "protocols.disabled";
        final String defaultValue = "SSLv1,SSLv2,SSLv2Hello,SSLv3";

        if ( type.getFallback() == null )
        {
            return JiveGlobals.getProperty( propertyName, defaultValue ).trim();
        }
        else
        {
            return JiveGlobals.getProperty( propertyName, getConnectionListener( type.getFallback() ).getEncryptionProtocolsDisabledCommaSeparated() ).trim();
        }
    }

    /**
     * A collection of cipher suite names that can be used for encryption of connections.
     *
     * When non-empty, the list is intended to specify those cipher suites (from a larger collection of implementation-
     * supported cipher suties) that can be used to establish encryption.
     *
     * Values returned by {@link #getCipherSuitesDisabled()} are not included in the result of this method.
     *
     * The order over which values are iterated in the result is equal to the order of values in the comma-separated
     * configuration string. This can, but is not guaranteed to, indicate preference.
     *
     * @return An (ordered) set of cipher suites, never null but possibly empty.
     */
    // TODO add setter!
    public Set<String> getCipherSuitesEnabled()
    {
        final Set<String> result = new LinkedHashSet<>();
        final String csv = getCipherSuitesEnabledCommaSeparated();
        result.addAll( Arrays.asList( csv.split( "\\s*,\\s*" ) ) );
        result.removeAll( getCipherSuitesDisabled() );
        return result;
    }

    protected String getCipherSuitesEnabledCommaSeparated()
    {
        final String propertyName = type.getPrefix() + "ciphersuites.enabled";
        final String defaultValue = "";

        if ( type.getFallback() == null )
        {
            return JiveGlobals.getProperty( propertyName, defaultValue );
        }
        else
        {
            return JiveGlobals.getProperty( propertyName, getConnectionListener( type.getFallback() ).getCipherSuitesEnabledCommaSeparated() );
        }
    }

    /**
     * A collection of cipher suites that must not be used for encryption of connections.
     *
     * When non-empty, the list is intended to specify those cipher suites (from a larger collection of implementation-
     * supported cipher suites) that must not be used to establish encryption.
     *
     * The order over which values are iterated in the result is equal to the order of values in the comma-separated
     * configuration string.
     *
     * @return An (ordered) set of cipher suites, never null but possibly empty.
     */
    // TODO add setter!
    public Set<String> getCipherSuitesDisabled()
    {
        final Set<String> result = new LinkedHashSet<>();
        final String csv = getCipherSuitesDisabledCommaSeparated();
        result.addAll( Arrays.asList( csv.split( "\\s*,\\s*" ) ) );
        return result;
    }

    protected String getCipherSuitesDisabledCommaSeparated()
    {
        final String propertyName = type.getPrefix() + "ciphersuites.disabled";
        final String defaultValue = "";

        if ( type.getFallback() == null )
        {
            return JiveGlobals.getProperty( propertyName, defaultValue ).trim();
        }
        else
        {
            return JiveGlobals.getProperty( propertyName, getConnectionListener( type.getFallback() ).getCipherSuitesDisabledCommaSeparated() ).trim();
        }
    }

    /**
     * Constructs and returns a ServerPort instance that reflects the state of this listener.
     *
     * @return A ServerPort instance, or null when the listener is not enabled.
     * @deprecated To obtain the state of this instance, use corresponding getters instead.
     */
    @Deprecated
    public ServerPort getServerPort()
    {
        if ( connectionAcceptor == null )
        {
            return null;
        }

        final int port = getPort();
        final String name = getBindAddress().getHostName();
        final String address = getBindAddress().getHostAddress();
        final boolean isSecure = getTLSPolicy() != Connection.TLSPolicy.disabled;
        final String algorithm = null;

        switch ( type ) {
            case SOCKET_C2S:
                return new ServerPort( port, name, address, isSecure, algorithm, ServerPort.Type.client );
            case SOCKET_S2S:
                return new ServerPort( port, name, address, isSecure, algorithm, ServerPort.Type.server );
            case COMPONENT:
                return new ServerPort( port, name, address, isSecure, algorithm, ServerPort.Type.component );
            case CONNECTION_MANAGER:
                return new ServerPort( port, name, address, isSecure, algorithm, ServerPort.Type.connectionManager );
            default:
                throw new IllegalStateException( "Unrecognized type: " + type );
        }
    }
    @Override
    public String toString()
    {
        final String name = getType().toString().toLowerCase() + ( getTLSPolicy().equals( Connection.TLSPolicy.legacyMode ) ? "-legacyMode" : "" );
        return "ConnectionListener{" +
                "name=" + name +
                '}';
    }

}
