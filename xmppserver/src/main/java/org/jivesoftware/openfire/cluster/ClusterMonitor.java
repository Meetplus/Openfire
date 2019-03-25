package org.jivesoftware.openfire.cluster;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Module;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Monitors the state of the cluster, and warns admins when nodes leave or rejoin the cluster
 */
public class ClusterMonitor implements Module, ClusterEventListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClusterMonitor.class);
    private static final String MODULE_NAME = "Cluster monitor";
    private static final String UNKNOWN_NODE_NAME = "<unknown>";
    private final Map<NodeID, String> nodeNames = new ConcurrentHashMap<>();
    private boolean nodeHasLeftCluster = false;
    private XMPPServer xmppServer;

    @SuppressWarnings("WeakerAccess")
    public ClusterMonitor() {
        LOGGER.debug("{} has been instantiated", MODULE_NAME);
    }

    @Override
    public String getName() {
        return MODULE_NAME;
    }

    @Override
    public void initialize(final XMPPServer xmppServer) {
        this.xmppServer = xmppServer;
        LOGGER.debug("{} has been initialized", MODULE_NAME);
    }

    @Override
    public void start() {
        ClusterManager.addListener(this);
        LOGGER.debug("{} has been started", MODULE_NAME);
    }

    @Override
    public void stop() {
        ClusterManager.removeListener(this);
        LOGGER.debug("{} has been stopped", MODULE_NAME);
    }

    @Override
    public void destroy() {
        LOGGER.debug("{} has been destroyed", MODULE_NAME);
    }

    @Override
    public void joinedCluster() {
        LOGGER.info("This node ({}/{}) has joined the cluster", xmppServer.getNodeID(), xmppServer.getServerInfo().getHostname());
    }

    @Override
    public void joinedCluster(final byte[] nodeIdBytes) {
        final String nodeName = getNodeName(nodeIdBytes);
        final NodeID nodeId = NodeID.getInstance(nodeIdBytes);
        nodeNames.put(nodeId, nodeName);
        LOGGER.info("Another node ({}/{}) has joined the cluster", nodeId, nodeName);
        if (ClusterManager.isSeniorClusterMember() && nodeHasLeftCluster) {
            xmppServer.sendMessageToAdmins(nodeName + " has joined the cluster - resilience is restored");
        }
    }

    @Override
    public void leftCluster() {
        final String nodeName = xmppServer.getServerInfo().getHostname();
        LOGGER.info("This node ({}/{}) has left the cluster", xmppServer.getNodeID(), nodeName);
        xmppServer.sendMessageToAdmins("The local node ('" + nodeName + "') has left the cluster - this node no longer has any resilience");
    }

    @Override
    public void leftCluster(final byte[] nodeIdBytes) {
        nodeHasLeftCluster = true;
        final NodeID nodeID = NodeID.getInstance(nodeIdBytes);
        final String nodeName = Optional.ofNullable(nodeNames.remove(nodeID)).orElse(UNKNOWN_NODE_NAME);
        LOGGER.info("Another node ({}/{}) has left the cluster", nodeID, nodeName);
        if (ClusterManager.isSeniorClusterMember()) {
            final int clusterSize = ClusterManager.getNodesInfo().size();
            final String conjunction;
            final String plural;
            if (clusterSize == 1) {
                conjunction = "is";
                plural = "";
            } else {
                conjunction = "are";
                plural = "s";
            }
            xmppServer.sendMessageToAdmins(nodeName + " has left the cluster - there " + conjunction + " now only " + clusterSize + " node" + plural + " in the cluster");
        }
    }

    @Override
    public void markedAsSeniorClusterMember() {
        LOGGER.info("This node ({}/{}) is now the senior member", xmppServer.getNodeID(), xmppServer.getServerInfo().getHostname());
    }

    private String getNodeName(final byte[] nodeID) {
        final Optional<ClusterNodeInfo> nodeInfo = ClusterManager.getNodeInfo(nodeID);
        return nodeInfo.map(ClusterNodeInfo::getHostName).orElse(UNKNOWN_NODE_NAME);
    }

}
