/*
 * Copyright (C) 2021 Ignite Realtime Foundation. All rights reserved.
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

package org.jivesoftware.util.cache;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.cluster.ClusterManager;
import org.jivesoftware.openfire.cluster.ClusterNodeInfo;
import org.jivesoftware.openfire.cluster.NodeID;
import org.jivesoftware.openfire.session.LocalClientSession;
import org.jivesoftware.openfire.spi.ClientRoute;
import org.jivesoftware.util.CollectionUtils;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This class defines methods that verify that the state of a cache and it's various supporting data structures (in which
 * some data duplication is expected) is consistent.
 *
 * This code has been taken from the classes that are responsible for maintaining the cache to reduce the code complexity
 * of those classes.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class ConsistencyChecks
{
    /**
     * Verifies that userCache, anonymousUserCache, localRoutingTable.getClientRoutes and routeOwnersByClusterNode
     * are in a consistent state.
     *
     * Note that this operation can be costly in terms of resource usage. Use with caution in large / busy systems.
     *
     * The returned multi-map can contain up to four keys: info, fail, pass, data. All entry values are a human readable
     * description of a checked characteristic. When the state is consistent, no 'fail' entries will be returned.
     *
     * @return A consistency state report.
     * @param usersCache The cache that is used to share data across cluster nodes
     * @param anonymousUsersCache The cache that is used to share data across cluster nodes
     * @param localClientRoutes The data structure that keeps track of what data was added to the cache by the local cluster node.
     * @param routeOwnersByClusterNode The data structure that keeps track of what data was added to the cache by the remote cluster nodes.
     */
    public static Multimap<String, String> generateReportForRoutingTableClientRoutes(
            @Nonnull final Cache<String, ClientRoute> usersCache,
            @Nonnull final Cache<String, ClientRoute> anonymousUsersCache,
            @Nonnull final Collection<LocalClientSession> localClientRoutes,
            @Nonnull final Map<NodeID, Set<String>> routeOwnersByClusterNode)
    {
        final Set<NodeID> clusterNodeIDs = ClusterManager.getNodesInfo().stream().map(ClusterNodeInfo::getNodeID).collect(Collectors.toSet());

        // Take snapshots of all data structures at as much the same time as possible.
        final Set<String> usersCacheKeySet = usersCache.keySet();
        final Set<String> anonymousUsersCacheKeySet = anonymousUsersCache.keySet();

        final Set<String> userRouteCachesDuplicates = CollectionUtils.findDuplicates(usersCacheKeySet, anonymousUsersCacheKeySet);

        final List<String> localClientRoutesOwners = localClientRoutes.stream().map(r->r.getAddress().toString()).collect(Collectors.toList());
        final Set<String> localClientRoutesOwnersDuplicates = CollectionUtils.findDuplicates(localClientRoutesOwners);

        final List<String> remoteClientRoutesOwners = routeOwnersByClusterNode.values().stream().flatMap(Collection::stream).collect(Collectors.toList());
        final List<String> remoteClientRoutesOwnersWithNodeId = new ArrayList<>();
        for (Map.Entry<NodeID, Set<String>> entry : routeOwnersByClusterNode.entrySet()) {
            for(String item : entry.getValue()) {
                remoteClientRoutesOwnersWithNodeId.add(item + " (" + entry.getKey() + ")");
            }
        }

        final Set<String> remoteClientRoutesOwnersDuplicates = CollectionUtils.findDuplicates(remoteClientRoutesOwners);

        final Set<String> clientRoutesBothLocalAndRemote = CollectionUtils.findDuplicates(localClientRoutesOwners, remoteClientRoutesOwners);

        final Multimap<String, String> result = HashMultimap.create();

        result.put("info", String.format("Two caches are used to share data in the cluster: %s and %s, which contain %d and %d user routes respectively (%d combined).", usersCache.getName(), anonymousUsersCache.getName(), usersCacheKeySet.size(), anonymousUsersCacheKeySet.size(), usersCacheKeySet.size() + anonymousUsersCacheKeySet.size() ) );
        result.put("info", String.format("LocalRoutingTable's getClientRoutes() response is used to track 'local' data to be restored after a cache switch-over (for both caches). It tracks %d routes.", localClientRoutes.size() ) );
        result.put("info", String.format("The field routeOwnersByClusterNode is used to track data in the cache from every other cluster node. It contains %d routes for %d cluster nodes.", routeOwnersByClusterNode.values().stream().reduce(0, (subtotal, values) -> subtotal + values.size(), Integer::sum), routeOwnersByClusterNode.keySet().size() ) );

        result.put("data", String.format("%s contains these entries (these are shared in the cluster):\n%s", usersCache.getName(), String.join("\n", usersCacheKeySet)));
        result.put("data", String.format("%s contains these entries (these are shared in the cluster):\n%s", anonymousUsersCache.getName(), String.join("\n", anonymousUsersCacheKeySet)));
        result.put("data", String.format("LocalRoutingTable's getClientRoutes() response contains these entries (these represent 'local' data):\n%s", String.join("\n", localClientRoutesOwners)));
        result.put("data", String.format("routeOwnersByClusterNode contains these entries (these represent 'remote' data):\n%s", String.join("\n", remoteClientRoutesOwnersWithNodeId)));

        if (userRouteCachesDuplicates.isEmpty()) {
            result.put("pass", String.format("There is no overlap in keys of the %s and %s (They are all unique values).", usersCache.getName(), anonymousUsersCache.getName()) );
        } else {
            result.put("fail", String.format("There is overlap in keys of the %s and %s caches (They are not all unique values). These %d values exist in both caches: %s", usersCache.getName(), anonymousUsersCache.getName(), userRouteCachesDuplicates.size(), String.join(", ", userRouteCachesDuplicates) ) );
        }

        if (localClientRoutesOwnersDuplicates.isEmpty()) {
            result.put("pass", "There is no overlap in route owners of LocalRoutingTable's getClientRoutes() response (They are all unique values).");
        } else {
            result.put("fail", String.format("There is overlap in route owners of LocalRoutingTable's getClientRoutes() response (They are not all unique values). These %d values are duplicated: %s", localClientRoutesOwnersDuplicates.size(), String.join(", ", localClientRoutesOwnersDuplicates) ) );
        }

        if (remoteClientRoutesOwnersDuplicates.isEmpty()) {
            result.put("pass", "There is no overlap in routeOwnersByClusterNode (They are all unique values).");
        } else {
            result.put("fail", String.format("There is overlap in routeOwnersByClusterNode (They are not all unique values). These %d values are duplicated: %s", remoteClientRoutesOwnersDuplicates.size(), String.join(", ", remoteClientRoutesOwnersDuplicates) ) );
        }

        if (!routeOwnersByClusterNode.containsKey(XMPPServer.getInstance().getNodeID())) {
            result.put("pass", "routeOwnersByClusterNode does not track data for the local cluster node.");
        } else {
            result.put("fail", "routeOwnersByClusterNode tracks data for the local cluster node.");
        }

        if (clusterNodeIDs.containsAll(routeOwnersByClusterNode.keySet())) {
            result.put("pass", "routeOwnersByClusterNode tracks data for cluster nodes that are recognized in the cluster.");
        } else {
            result.put("fail", String.format("routeOwnersByClusterNode tracks data for cluster nodes that are not recognized. All cluster nodeIDs as recognized: %s All cluster nodeIDs for which data is tracked: %s.", clusterNodeIDs.stream().map(NodeID::toString).collect(Collectors.joining(", ")), routeOwnersByClusterNode.keySet().stream().map(NodeID::toString).collect(Collectors.joining(", "))));
        }

        if (clientRoutesBothLocalAndRemote.isEmpty()) {
            result.put("pass", "There are no locally stored element that are both 'remote' (in routeOwnersByClusterNode) as well as 'local' (in LocalRoutingTable's getClientRoutes()).");
        } else {
            result.put("fail", String.format("There are %d locally stored element that are both 'remote' (in routeOwnersByClusterNode) as well as 'local' (in LocalRoutingTable's getClientRoutes()): %s", clientRoutesBothLocalAndRemote.size(), String.join(", ", clientRoutesBothLocalAndRemote)) );
        }

        final Set<String> nonCachedLocalClientRoutesOwners = localClientRoutesOwners.stream().filter( v -> !usersCacheKeySet.contains(v) ).filter( v -> !anonymousUsersCacheKeySet.contains(v)).collect(Collectors.toSet());
        if (nonCachedLocalClientRoutesOwners.isEmpty()) {
            result.put("pass", String.format("All route owners of LocalRoutingTable's getClientRoutes() response exist in %s and/or %s.", usersCache.getName(), anonymousUsersCache.getName()) );
        } else {
            result.put("fail", String.format("Not all route owners of LocalRoutingTable's getClientRoutes() response exist in %s and/or %s. These %d entries do not: %s", usersCache.getName(), anonymousUsersCache.getName(), nonCachedLocalClientRoutesOwners.size(), String.join(", ", nonCachedLocalClientRoutesOwners)) );
        }

        final Set<String> nonCacheRemoteClientRouteOwners = remoteClientRoutesOwners.stream().filter( v -> !usersCacheKeySet.contains(v) ).filter( v -> !anonymousUsersCacheKeySet.contains(v)).collect(Collectors.toSet());
        if (nonCacheRemoteClientRouteOwners.isEmpty()) {
            result.put("pass", String.format("All route owners in routeOwnersByClusterNode exist in %s and/or %s.", usersCache.getName(), anonymousUsersCache.getName()) );
        } else {
            result.put("fail", String.format("Not all route owners in routeOwnersByClusterNode exist in %s and/or %s. These %d entries do not: %s", usersCache.getName(), anonymousUsersCache.getName(), nonCacheRemoteClientRouteOwners.size(), String.join(", ", nonCacheRemoteClientRouteOwners)) );
        }

        final Set<String> nonLocallyStoredCachedRouteOwners = usersCacheKeySet.stream().filter( v -> !localClientRoutesOwners.contains(v) ).filter( v -> !remoteClientRoutesOwners.contains(v) ).collect(Collectors.toSet());
        if (nonLocallyStoredCachedRouteOwners.isEmpty()) {
            result.put("pass", String.format("All cache entries of %s exist in routeOwnersByClusterNode and/or LocalRoutingTable's getClientRoutes() response.", usersCache.getName() ) );
        } else {
            result.put("fail", String.format("Not cache entries of %s exist in routeOwnersByClusterNode and/or LocalRoutingTable's getClientRoutes() response. These %d entries do not: %s", usersCache.getName(), nonLocallyStoredCachedRouteOwners.size(), String.join(", ", nonLocallyStoredCachedRouteOwners)) );
        }

        final Set<String> nonLocallyStoredCachedAnonRouteOwners = anonymousUsersCacheKeySet.stream().filter( v -> !localClientRoutesOwners.contains(v) ).filter( v -> !remoteClientRoutesOwners.contains(v) ).collect(Collectors.toSet());
        if (nonLocallyStoredCachedAnonRouteOwners.isEmpty()) {
            result.put("pass", String.format("All cache entries of %s exist in routeOwnersByClusterNode and/or LocalRoutingTable's getClientRoutes() response.", anonymousUsersCache.getName() ) );
        } else {
            result.put("fail", String.format("Not cache entries of %s exist in routeOwnersByClusterNode and/or LocalRoutingTable's getClientRoutes() response. These %d entries do not: %s", anonymousUsersCache.getName(), nonLocallyStoredCachedAnonRouteOwners.size(), String.join(", ", nonLocallyStoredCachedAnonRouteOwners)) );
        }

        return result;
    }
}
