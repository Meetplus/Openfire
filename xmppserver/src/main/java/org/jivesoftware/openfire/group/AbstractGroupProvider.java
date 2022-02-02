package org.jivesoftware.openfire.group;

import java.io.Serializable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.Lock;

import com.google.common.collect.Interner;
import com.google.common.collect.Interners;
import org.apache.commons.lang3.StringUtils;
import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.event.GroupEventDispatcher;
import org.jivesoftware.openfire.event.GroupEventListener;
import org.jivesoftware.util.CacheableOptional;
import org.jivesoftware.util.cache.Cache;
import org.jivesoftware.util.cache.CacheFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jivesoftware.util.PersistableMap;
import org.xmpp.packet.JID;

/**
 * Shared base class for Openfire GroupProvider implementations. By default
 * all mutator methods throw {@link UnsupportedOperationException}. In
 * addition, group search operations are disabled.
 * 
 * Subclasses may optionally implement these capabilities, and must also
 * at minimum implement the {@link GroupProvider#getGroup(String)} method.
 *
 * @author Tom Evans
 */
public abstract class AbstractGroupProvider implements GroupProvider {
    
    private static final Logger Log = LoggerFactory.getLogger(AbstractGroupProvider.class);

    private static final String GROUPLIST_CONTAINERS =
            "SELECT groupName from ofGroupProp " +
            "where name='sharedRoster.groupList' " +
            "AND propValue LIKE ?";
    private static final String PUBLIC_GROUPS_SQL =
            "SELECT groupName from ofGroupProp " +
            "WHERE name='sharedRoster.showInRoster' " +
            "AND propValue='everybody'";
    private static final String GROUPS_FOR_PROP = 
            "SELECT groupName from ofGroupProp " +
            "WHERE name=? " +
            "AND propValue=?";
    private static final String LOAD_SHARED_GROUPS =
            "SELECT groupName FROM ofGroupProp WHERE name='sharedRoster.showInRoster' " +
            "AND propValue IS NOT NULL AND propValue <> 'nobody'";
    private static final String LOAD_PROPERTIES =
            "SELECT name, propValue FROM ofGroupProp WHERE groupName=?";

    private static final Interner<JID> userBasedMutex = Interners.newWeakInterner();

    private static final String SHARED_GROUPS_KEY = "SHARED_GROUPS";
    private static final String PUBLIC_GROUPS = "PUBLIC_GROUPS";
    private static final String USER_SHARED_GROUPS_KEY = "USER_SHARED_GROUPS";
    private static final String GROUP_SHARED_GROUPS_KEY = "GROUP_SHARED_GROUPS";

    private final Cache<String, Serializable> sharedGroupMetaCache = CacheFactory.createLocalCache("Group (Shared) Metadata Cache");

    protected AbstractGroupProvider() {

        GroupEventDispatcher.addListener(new GroupEventListener() {
            @Override
            public void groupCreated(Group group, Map params) {
                synchronized (sharedGroupMetaCache) {
                    sharedGroupMetaCache.clear();
                }
            }

            @Override
            public void groupDeleting(Group group, Map params) {
                synchronized (sharedGroupMetaCache) {
                    sharedGroupMetaCache.clear();
                }
            }

            @Override
            public void groupModified(Group group, Map params) {
                synchronized (sharedGroupMetaCache) {
                    sharedGroupMetaCache.clear();
                }
            }

            @Override
            public void memberAdded(Group group, Map params) {
                synchronized (sharedGroupMetaCache) {
                    sharedGroupMetaCache.clear();
                }
            }

            @Override
            public void memberRemoved(Group group, Map params) {
                synchronized (sharedGroupMetaCache) {
                    sharedGroupMetaCache.clear();
                }
            }

            @Override
            public void adminAdded(Group group, Map params) {
                synchronized (sharedGroupMetaCache) {
                    sharedGroupMetaCache.clear();
                }
            }

            @Override
            public void adminRemoved(Group group, Map params) {
                synchronized (sharedGroupMetaCache) {
                    sharedGroupMetaCache.clear();
                }
            }
        });
    }
    // Mutator methods disabled for read-only group providers

    /**
     * @throws UnsupportedOperationException if the provider is read only
     */
    @Override
    public void addMember(String groupName, JID user, boolean administrator) throws GroupNotFoundException {
        throw new UnsupportedOperationException("Cannot add members to read-only groups");
    }

    /**
     * @throws UnsupportedOperationException if the provider is read only
     */
    @Override
    public void updateMember(String groupName, JID user, boolean administrator)
    {
        throw new UnsupportedOperationException("Cannot update members for read-only groups");
    }

    /**
     * @throws UnsupportedOperationException if the provider is read only
     */
    @Override
    public void deleteMember(String groupName, JID user)
    {
        throw new UnsupportedOperationException("Cannot remove members from read-only groups");
    }

    /**
     * Always true for a read-only provider
     */
    @Override
    public boolean isReadOnly() {
        return true;
    }

    /**
     * @throws UnsupportedOperationException if the provider is read only
     */
    @Override
    public Group createGroup(String name) throws GroupAlreadyExistsException, GroupNameInvalidException {
        throw new UnsupportedOperationException("Cannot create groups via read-only provider");
    }

    /**
     * @throws UnsupportedOperationException if the provider is read only
     */
    @Override
    public void deleteGroup(String name) throws GroupNotFoundException {
        throw new UnsupportedOperationException("Cannot remove groups via read-only provider");
    }

    /**
     * @throws GroupAlreadyExistsException if the group alrady exists
     * @throws UnsupportedOperationException if the provider is read only
     */
    @Override
    public void setName(String oldName, String newName) throws GroupAlreadyExistsException, GroupNameInvalidException, GroupNotFoundException {
        throw new UnsupportedOperationException("Cannot modify read-only groups");
    }

    /**
     * @throws GroupNotFoundException if the group could not be found
     * @throws UnsupportedOperationException if the provider is read only
     */
    @Override
    public void setDescription(String name, String description) throws GroupNotFoundException {
        throw new UnsupportedOperationException("Cannot modify read-only groups");
    }

    // Search methods may be overridden by read-only group providers
    
    /**
     * Returns true if the provider supports group search capability. This implementation
     * always returns false.
     */
    @Override
    public boolean isSearchSupported() {
        return false;
    }

    /**
     * Returns a collection of group search results. This implementation
     * returns an empty collection.
     */
    @Override
    public Collection<String> search(String query) {
        return Collections.emptyList();
    }

    /**
     * Returns a collection of group search results. This implementation
     * returns an empty collection.
     */
    @Override
    public Collection<String> search(String query, int startIndex, int numResults) {
        return Collections.emptyList();
    }

    // Shared group methods may be overridden by read-only group providers

    /**
     * Returns the name of the groups that are shared groups.
     *
     * @return the name of the groups that are shared groups.
     */
    @Override
    public Collection<String> getSharedGroupNames() {
        HashSet<String> groupNames;
        synchronized (sharedGroupMetaCache) {
            groupNames = getSharedGroupsFromCache();
            if (groupNames != null) {
                return groupNames;
            }

            groupNames = new HashSet<>();
            Connection con = null;
            PreparedStatement pstmt = null;
            ResultSet rs = null;
            try {
                con = DbConnectionManager.getConnection();
                pstmt = con.prepareStatement(LOAD_SHARED_GROUPS);
                rs = pstmt.executeQuery();
                while (rs.next()) {
                    groupNames.add(rs.getString(1));
                }
                saveSharedGroupsInCache(groupNames);
            } catch (SQLException sqle) {
                Log.error(sqle.getMessage(), sqle);
            } finally {
                DbConnectionManager.closeConnection(rs, pstmt, con);
            }
        }
        return groupNames;
    }

    @Override
    public Collection<String> getSharedGroupNames(JID user) {
        HashSet<String> groupNames;
        synchronized (sharedGroupMetaCache) {
            groupNames = getSharedGroupsForUserFromCache(user.getNode());
            if (groupNames == null) {
                groupNames = new HashSet<>();
                if (!getSharedGroupNames().isEmpty()) {
                    for (String userGroup : getGroupNames(user)) {
                        groupNames.addAll(getVisibleGroupNames(userGroup));
                    }
                    groupNames.addAll(getPublicSharedGroupNames());
                }
                saveSharedGroupsForUserInCache(user.getNode(), groupNames);
            }
        }

        return groupNames;
    }

    @Override
    public Collection<String> getVisibleGroupNames(String userGroup) {
        HashSet<String> groupNames;

        synchronized (sharedGroupMetaCache) {
            groupNames = getSharedGroupsForGroupFromCache(userGroup);
            if (groupNames != null) {
                return groupNames;
            }

            groupNames = new HashSet<>();
            Connection con = null;
            PreparedStatement pstmt = null;
            ResultSet rs = null;
            try {
                con = DbConnectionManager.getConnection();
                pstmt = con.prepareStatement(GROUPLIST_CONTAINERS);
                pstmt.setString(1, "%" + userGroup + "%");
                rs = pstmt.executeQuery();
                while (rs.next()) {
                    groupNames.add(rs.getString(1));
                }

                saveSharedGroupsForGroupInCache(userGroup, groupNames);
            } catch (SQLException sqle) {
                Log.error(sqle.getMessage(), sqle);
            } finally {
                DbConnectionManager.closeConnection(rs, pstmt, con);
            }
        }
        return groupNames;
    }
    
    @Override
    public Collection<String> search(String key, String value) {
        Set<String> groupNames = new HashSet<>();
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement(GROUPS_FOR_PROP);
            pstmt.setString(1, key);
            pstmt.setString(2, value);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                groupNames.add(rs.getString(1));
            }
        }
        catch (SQLException sqle) {
            Log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }
        return groupNames;
    }

    @Override
    public Collection<String> getPublicSharedGroupNames() {
        HashSet<String> groupNames;
        synchronized (sharedGroupMetaCache) {
            groupNames = getPublicGroupsFromCache();
            if (groupNames != null) {
                return groupNames;
            }

            groupNames = new HashSet<>();
            Connection con = null;
            PreparedStatement pstmt = null;
            ResultSet rs = null;
            try {
                con = DbConnectionManager.getConnection();
                pstmt = con.prepareStatement(PUBLIC_GROUPS_SQL);
                rs = pstmt.executeQuery();
                while (rs.next()) {
                    groupNames.add(rs.getString(1));
                }
                savePublicGroupsInCache(groupNames);
            } catch (SQLException sqle) {
                Log.error(sqle.getMessage(), sqle);
            } finally {
                DbConnectionManager.closeConnection(rs, pstmt, con);
            }
            return groupNames;
        }
    }

    @Override
    public boolean isSharingSupported() {
        return true;
    }

    /**
     * Returns a custom {@link Map} that updates the database whenever
     * a property value is added, changed, or deleted.
     * 
     * @param group The target group
     * @return The properties for the given group
     */
    @Override
    public PersistableMap<String,String> loadProperties(Group group) {
        // custom map implementation persists group property changes
        // whenever one of the standard mutator methods are called
        String name = group.getName();
        PersistableMap<String,String> result = new DefaultGroupPropertyMap<>(group);
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement(LOAD_PROPERTIES);
            pstmt.setString(1, name);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                String key = rs.getString(1);
                String value = rs.getString(2);
                if (key != null) {
                    if (value == null) {
                        result.remove(key);
                        Log.warn("Deleted null property " + key + " for group: " + name);
                    } else {
                        result.put(key, value, false); // skip persistence during load
                    }
                }
                else { // should not happen, but ...
                    Log.warn("Ignoring null property key for group: " + name);
                }
            }
        }
        catch (SQLException sqle) {
            Log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private HashSet<String> getSharedGroupsFromCache() {
        synchronized (sharedGroupMetaCache) {
            return (HashSet<String>) sharedGroupMetaCache.get(SHARED_GROUPS_KEY);
        }
    }

    private void saveSharedGroupsInCache(final HashSet<String> groupNames) {
        synchronized (sharedGroupMetaCache) {
            sharedGroupMetaCache.put(SHARED_GROUPS_KEY, groupNames);
        }
    }

    private String getSharedGroupsForUserKey(final String userName) {
        return USER_SHARED_GROUPS_KEY + userName;
    }

    @SuppressWarnings("unchecked")
    private HashSet<String> getSharedGroupsForUserFromCache(final String userName) {
        synchronized (sharedGroupMetaCache) {
            return (HashSet<String>) sharedGroupMetaCache.get(getSharedGroupsForUserKey(userName));
        }
    }

    private void saveSharedGroupsForUserInCache(final String userName, final HashSet<String> groupNames) {
        synchronized (sharedGroupMetaCache) {
            sharedGroupMetaCache.put(getSharedGroupsForUserKey(userName), groupNames);
        }
    }

    static String getSharedGroupsForGroupKey(final String groupName) {
        return GROUP_SHARED_GROUPS_KEY + groupName;
    }

    private HashSet<String> getSharedGroupsForGroupFromCache(final String groupName) {
        synchronized (sharedGroupMetaCache) {
            return (HashSet<String>) sharedGroupMetaCache.get(getSharedGroupsForGroupKey(groupName));
        }
    }

    private void saveSharedGroupsForGroupInCache(final String groupName, final HashSet<String> groupNames) {
        synchronized (sharedGroupMetaCache) {
            sharedGroupMetaCache.put(getSharedGroupsForGroupKey(groupName), groupNames);
        }
    }

    @SuppressWarnings("unchecked")
    private HashSet<String> getPublicGroupsFromCache() {
        synchronized (sharedGroupMetaCache) {
            return (HashSet<String>) sharedGroupMetaCache.get(PUBLIC_GROUPS);
        }
    }

    private void savePublicGroupsInCache(final HashSet<String> groupNames) {
        synchronized (sharedGroupMetaCache) {
            sharedGroupMetaCache.put(PUBLIC_GROUPS, groupNames);
        }
    }
}
