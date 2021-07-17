/*
 * Copyright (C) 2004-2008 Jive Software. All rights reserved.
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

package org.jivesoftware.openfire.muc;

import org.dom4j.Element;
import org.dom4j.QName;
import org.jivesoftware.openfire.ChannelHandler;
import org.jivesoftware.openfire.PacketException;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.cluster.NodeID;
import org.jivesoftware.openfire.handler.IQPingHandler;
import org.jivesoftware.openfire.stanzaid.StanzaIDUtil;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.LocaleUtils;
import org.jivesoftware.util.NotFoundException;
import org.jivesoftware.util.cache.CacheSizes;
import org.jivesoftware.util.cache.Cacheable;
import org.jivesoftware.util.cache.CannotCalculateSizeException;
import org.jivesoftware.util.cache.ExternalizableUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.locks.Lock;

/**
 * Representation of users interacting with the chat service. A user
 * may join several rooms hosted by the chat service. That means that
 * we are going to have an instance of this class for the user and several
 * MUCRoles for each joined room.
 *
 * The chat user is a separate user abstraction for interacting with
 * the chat server. Centralizing chat users to the Jabber entity that
 * sends and receives the chat messages allows us to create quality of
 * service, authorization, and resource decisions on a real-user basis.
 *
 * Most chat users in a typical s2s scenario will not be local users.
 *
 * MUCUsers play one or more roles in one or more chat rooms on the
 * server.
 *
 * @author Gaston Dombiak
 */
public class MUCUser implements ChannelHandler<Packet>, Cacheable, Externalizable
{
    private static final Logger Log = LoggerFactory.getLogger(MUCUser.class);

    /**
     * The name of the chat service that this user belongs to.
     */
    // Only set during construction or when deserialized. Would have been 'final' if not for implementing Externalizable
    private String serviceName;

    /**
     * The chat service that this user belongs to. Lazily initiated by {@link #getChatService()}
     */
    private transient MultiUserChatService service;

    /**
     * Real system XMPPAddress for the user.
     */
    // Only set during construction or when deserialized. Would have been 'final' if not for implementing Externalizable
    private JID realjid;

    /**
     * Names of the rooms (in this chat service) in which this user has a MUCRole.
     */
    private Set<String> roomNames = new HashSet<>();

    /**
     * Time of last packet sent.
     */
    private Instant lastPacketTime;

    /**
     * This constructor is provided to comply with the Externalizable interface contract. It should not be used directly.
     */
    public MUCUser()
    {}

    /**
     * Create a new chat user.
     *
     * @param chatservice  the service the user belongs to.
     * @param jid          the real address of the user
     */
    public MUCUser(MultiUserChatService chatservice, JID jid )
    {
        this.realjid = jid;
        this.serviceName = chatservice.getServiceName();
        this.service = chatservice;
    }

    private synchronized MultiUserChatService getChatService() {
        if (service == null) {
            service = XMPPServer.getInstance().getMultiUserChatManager().getMultiUserChatService(serviceName);
        }

        return service;
    }

    /**
     * Returns true if the user is currently present in one or more rooms.
     *
     * @return true if the user is currently present in one or more rooms.
     */
    public boolean isJoined()
    {
        return !roomNames.isEmpty();
    }

    /**
     * Get the names of all rooms that this user has a role in.
     *
     * @return An unmodifiable collection of all room names for this MUCUser.
     */
    // TODO: it is expected that every Room in this collection contains a MUCRole for this user, and vice versa. Can this be guaranteed?
    public Collection<String> getRoomNames() { return Collections.unmodifiableCollection(roomNames); }

    /**
     * Register that this user has a role in a particular room.
     *
     * It is imperative that the content of #roomNames and MUCRoom#occupants are kept in sync. This method
     * should therefore only, and exclusively, be called by methods that add content to that cache (such as
     * {@link MUCRoom#addOccupantRole(MUCRole)})
     *
     * @param roomName name of a MUC room.
     */
    void addRoomName(String roomName) {
        roomNames.add(roomName);
        // FIXME persist this change in the cache that holds all MUCUser instances!
    }

    /**
     * Remove registration of role for a user in a particular room.
     *
     * It is imperative that the content of #roomNames and MUCRoom#occupants are kept in sync. This method
     * should therefore only, and exclusively, be called by methods that remove content from that cache (such as
     * {@link MUCRoom#removeOccupantRole(MUCRole)})
     *
     * @param roomName name of a MUC room.
     */
    void removeRoomName(String roomName) {
        roomNames.remove(roomName);
        // FIXME persist this change in the cache that holds all MUCUser instances!
    }

    /**
     * Get instant when the last packet was sent from this user.
     *
     * @return The time when the last packet was sent from this user
     */
    public Instant getLastPacketTime()
    {
        return lastPacketTime;
    }

    /**
     * Generate and send an error packet to indicate that something went wrong.
     *
     * @param packet  the packet to be responded to with an error.
     * @param error   the reason why the operation failed.
     * @param message an optional human-readable error message.
     */
    private void sendErrorPacket( Packet packet, PacketError.Condition error, String message )
    {
        if ( packet instanceof IQ )
        {
            IQ reply = IQ.createResultIQ((IQ) packet);
            reply.setChildElement(((IQ) packet).getChildElement().createCopy());
            reply.setError(error);
            if ( message != null )
            {
                reply.getError().setText(message);
            }
            XMPPServer.getInstance().getPacketRouter().route(reply);
        }
        else
        {
            Packet reply = packet.createCopy();
            reply.setError(error);
            if ( message != null )
            {
                reply.getError().setText(message);
            }
            reply.setFrom(packet.getTo());
            reply.setTo(packet.getFrom());
            XMPPServer.getInstance().getPacketRouter().route(reply);
        }
    }

    /**
     * Generate and send an error packet to indicate that something went wrong when processing an FMUC join request.
     *
     * @param packet  the packet to be responded to with an error.
     * @param message an optional human-readable reject message.
     */
    private void sendFMUCJoinReject( Presence packet, String message )
    {
        final Presence reply = new Presence();

        // XEP-0289: "(..) To do this it sends a 'presence' reply from its bare JID to the bare JID of the joining node (..)"
        reply.setTo( packet.getFrom().asBareJID() );
        reply.setFrom( this.getAddress().asBareJID() );

        final Element reject = reply.addChildElement("fmuc", "http://isode.com/protocol/fmuc").addElement("reject");
        if ( message != null && !message.trim().isEmpty() ) {
            reject.addText( message );
        }
        XMPPServer.getInstance().getPacketRouter().route(reply);
    }

    /**
     * Obtain the address of the user. The address is used by services like the core server packet router to determine
     * if a packet should be sent to the handler. Handlers that are working on behalf of the server should use the
     * generic server hostname address (e.g. server.com).
     *
     * @return the address of the packet handler.
     */
    public JID getAddress()
    {
        return realjid;
    }

    /**
     * This method does all packet routing in the chat server. Packet routing is actually very simple:
     *
     * <ul>
     *   <li>Discover the room the user is talking to</li>
     *   <li>If the room is not registered and this is a presence "available" packet, try to join the room</li>
     *   <li>If the room is registered, and presence "unavailable" leave the room</li>
     *   <li>Otherwise, rewrite the sender address and send to the room.</li>
     * </ul>
     *
     * @param packet The stanza to route
     */
    @Override
    public void process( Packet packet ) throws UnauthorizedException, PacketException
    {
        // Name of the room that the stanza is addressed to.
        final String roomName = packet.getTo().getNode();

        if ( roomName == null )
        {
            // Packets to the groupchat service (as opposed to a specific room on the service). This should not occur
            // (should be handled by MultiUserChatServiceImpl instead).
            Log.warn(LocaleUtils.getLocalizedString("muc.error.not-supported") + " " + packet.toString());
            if ( packet instanceof IQ && ((IQ) packet).isRequest() )
            {
                sendErrorPacket(packet, PacketError.Condition.feature_not_implemented, "Unable to process stanza.");
            }
            return;
        }

        Log.trace("User '{}' is sending a packet to room '{}'", this.realjid, roomName);

        lastPacketTime = Instant.now();

        StanzaIDUtil.ensureUniqueAndStableStanzaID(packet, packet.getTo().asBareJID());

        final Lock lock = getChatService().getLock(roomName);
        lock.lock();
        try {
            // Get the room, if one exists.
            @Nullable MUCRoom room = getChatService().getChatRoom(roomName);

            // Determine if this user has a pre-existing role in the addressed room.
            final MUCRole preExistingRole;
            if (roomNames.contains(roomName)) {
                if (room == null) {
                    preExistingRole = null;
                } else {
                    preExistingRole = room.getOccupantByFullJID(getAddress());
                }
            } else {
                preExistingRole = null;
            }
            Log.debug("Preexisting role for user {} in room {} (that currently {} exist): {}", this.realjid, roomName, room == null ? "does not" : "does", preExistingRole == null ? "(none)" : preExistingRole);

            // Determine if the stanza is an error response to a stanza that we've previously sent out, that indicates that
            // the intended recipient is no longer available (eg: "ghost user").
            if (preExistingRole != null && getChatService().getIdleUserPingThreshold() != null && isDeliveryRelatedErrorResponse(packet)) {
                Log.info("Removing {} (nickname '{}') from room {} as we've received an indication (logged at debug level) that this is now a ghost user.", preExistingRole.getUserAddress(), preExistingRole.getNickname(), roomName);
                Log.debug("Stanza indicative of a ghost user: {}", packet);
                room.leaveRoom(preExistingRole);
                getChatService().syncChatRoom(room);
                return;
            }

            if ( packet instanceof IQ )
            {
                process((IQ) packet, room, preExistingRole);
            }
            else if ( packet instanceof Message )
            {
                process((Message) packet, room, preExistingRole);
            }
            else if ( packet instanceof Presence )
            {
                // Return value is non-null while argument is, in case this is a request to create a new room.
                room = process((Presence) packet, roomName, room, preExistingRole);
            }

            // Ensure that other cluster nodes see any changes that might have been applied.
            if (room != null) {
                getChatService().syncChatRoom(room);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Processes a Message stanza.
     *
     * @param packet          The stanza to route
     * @param room            The room that the stanza was addressed to.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza, if any.
     */
    private void process(
        @Nonnull final Message packet,
        @Nullable final MUCRoom room,
        @Nullable final MUCRole preExistingRole )
    {
        if (Message.Type.error == packet.getType()) {
            Log.trace("Ignoring messages of type 'error' sent by '{}' to MUC room '{}'", packet.getFrom(), packet.getTo());
            return;
        }

        if (room == null) {
            Log.debug("Rejecting message stanza sent by '{}' to room '{}': Room does not exist.", packet.getFrom(), packet.getTo());
            sendErrorPacket(packet, PacketError.Condition.recipient_unavailable, "The room that the message was addressed to is not available.");
            return;
        }

        if ( preExistingRole == null )
        {
            processNonOccupantMessage(packet, room);
        }
        else
        {
            processOccupantMessage(packet, room, preExistingRole);
        }
    }

    /**
     * Processes a Message stanza that was sent by a user that's not in the room.
     *
     * Only declined invitations (to join a room) are acceptable messages from users that are not in the room. Other
     * messages are responded to with an error.
     *
     * @param packet   The stanza to process
     * @param room     The room that the stanza was addressed to.
     */
    private void processNonOccupantMessage(
        @Nonnull final Message packet,
        @Nonnull final MUCRoom room )
    {
        boolean declinedInvitation = false;
        Element userInfo = null;
        if ( Message.Type.normal == packet.getType() )
        {
            // An user that is not an occupant could be declining an invitation
            userInfo = packet.getChildElement("x", "http://jabber.org/protocol/muc#user");
            if ( userInfo != null && userInfo.element("decline") != null )
            {
                // A user has declined an invitation to a room
                // WARNING: Potential fraud if someone fakes the "from" of the
                // message with the JID of a member and sends a "decline"
                declinedInvitation = true;
            }
        }

        if ( declinedInvitation )
        {
            Log.debug("Processing room invitation declination sent by '{}' to room '{}'.", packet.getFrom(), room.getName());
            final Element info = userInfo.element("decline");
            room.sendInvitationRejection(
                new JID(info.attributeValue("to")),
                info.elementTextTrim("reason"),
                packet.getFrom());
        }
        else
        {
            Log.debug("Rejecting message stanza sent by '{}' to room '{}': Sender is not an occupant of the room: {}", packet.getFrom(), room.getName(), packet.toXML());
            sendErrorPacket(packet, PacketError.Condition.not_acceptable, "You are not in the room.");
        }
    }

    /**
     * Processes a Message stanza that was sent by a user that's in the room.
     *
     * @param packet          The stanza to process
     * @param room            The room that the stanza was addressed to.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza, if any.
     */
    private void processOccupantMessage(
        @Nonnull final Message packet,
        @Nonnull final MUCRoom room,
        @Nonnull final MUCRole preExistingRole )
    {
        // Check and reject conflicting packets with conflicting roles In other words, another user already has this nickname
        if ( !preExistingRole.getUserAddress().equals(packet.getFrom()) )
        {
            Log.debug("Rejecting conflicting stanza with conflicting roles: {}", packet.toXML());
            sendErrorPacket(packet, PacketError.Condition.conflict, "Another user uses this nickname.");
            return;
        }

        if (room.getRoomHistory().isSubjectChangeRequest(packet))
        {
            processChangeSubjectMessage(packet, room, preExistingRole);
            return;
        }

        // An occupant is trying to send a private message, send public message, invite someone to the room or reject an invitation.
        final Message.Type type = packet.getType();
        String nickname = packet.getTo().getResource();
        if ( nickname == null || nickname.trim().length() == 0 )
        {
            nickname = null;
        }

        // Public message (not addressed to a specific occupant)
        if ( nickname == null && Message.Type.groupchat == type )
        {
            processPublicMessage(packet, room, preExistingRole);
            return;
        }

        // Private message (addressed to a specific occupant)
        if ( nickname != null && (Message.Type.chat == type || Message.Type.normal == type) )
        {
            processPrivateMessage(packet, room, preExistingRole);
            return;
        }

        if ( nickname == null && Message.Type.normal == type )
        {
            // An occupant could be sending an invitation or declining an invitation
            final Element userInfo = packet.getChildElement("x", "http://jabber.org/protocol/muc#user");

            if ( userInfo != null && userInfo.element("invite") != null )
            {
                // An occupant is sending invitations
                processSendingInvitationMessage(packet, room, preExistingRole);
                return;
            }

            if ( userInfo != null && userInfo.element("decline") != null )
            {
                // An occupant has declined an invitation
                processDecliningInvitationMessage(packet, room);
                return;
            }
        }

        Log.debug("Unable to process message: {}", packet.toXML());
        sendErrorPacket(packet, PacketError.Condition.bad_request, "Unable to process message.");
    }

    /**
     * Process a 'change subject' message sent by an occupant of the room.
     *
     * @param packet          The stanza to process
     * @param room            The room that the stanza was addressed to.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza, if any.
     */
    private void processChangeSubjectMessage(
        @Nonnull final Message packet,
        @Nonnull final MUCRoom room,
        @Nonnull final MUCRole preExistingRole )
    {
        Log.trace("Processing subject change request from occupant '{}' to room '{}'.", packet.getFrom(), room.getName());
        try
        {
            room.changeSubject(packet, preExistingRole);
        }
        catch ( ForbiddenException e )
        {
            Log.debug("Rejecting subject change request from occupant '{}' to room '{}'.", packet.getFrom(), room.getName(), e);
            sendErrorPacket(packet, PacketError.Condition.forbidden, "You are not allowed to change the subject of this room.");
        }
    }

    /**
     * Process a public message sent by an occupant of the room.
     *
     * @param packet          The stanza to process
     * @param room            The room that the stanza was addressed to.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza, if any.
     */
    private void processPublicMessage(
        @Nonnull final Message packet,
        @Nonnull final MUCRoom room,
        @Nonnull final MUCRole preExistingRole )
    {
        Log.trace("Processing public message from occupant '{}' to room '{}'.", packet.getFrom(), room.getName());
        try
        {
            room.sendPublicMessage(packet, preExistingRole);
        }
        catch ( ForbiddenException e )
        {
            Log.debug("Rejecting public message from occupant '{}' to room '{}'. User is not allowed to send message (might not have voice).", packet.getFrom(), room.getName(), e);
            sendErrorPacket(packet, PacketError.Condition.forbidden, "You are not allowed to send a public message to the room (you might require 'voice').");
        }
    }

    /**
     * Process a private message sent by an occupant of the room.
     *
     * @param packet          The stanza to process
     * @param room            The room that the stanza was addressed to.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza, if any.
     */
    private void processPrivateMessage(
        @Nonnull final Message packet,
        @Nonnull final MUCRoom room,
        @Nonnull final MUCRole preExistingRole )
    {
        Log.trace("Processing private message from occupant '{}' to room '{}'.", packet.getFrom(), room.getName());
        try
        {
            room.sendPrivatePacket(packet, preExistingRole);
        }
        catch ( ForbiddenException e )
        {
            Log.debug("Rejecting private message from occupant '{}' to room '{}'. User has a role that disallows sending private messages in this room.", packet.getFrom(), room.getName(), e);
            sendErrorPacket(packet, PacketError.Condition.forbidden, "You are not allowed to send a private messages in the room.");
        }
        catch ( NotFoundException e )
        {
            Log.debug("Rejecting private message from occupant '{}' to room '{}'. User addressing a non-existent recipient.", packet.getFrom(), room.getName(), e);
            sendErrorPacket(packet, PacketError.Condition.recipient_unavailable, "The intended recipient of your private message is not available.");
        }
    }

    /**
     * Process a room-invitation message sent by an occupant of the room.
     *
     * @param packet          The stanza to process
     * @param room            The room that the stanza was addressed to.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza, if any.
     */
    private void processSendingInvitationMessage(
        @Nonnull final Message packet,
        @Nonnull final MUCRoom room,
        @Nonnull final MUCRole preExistingRole )
    {
        Log.trace("Processing an invitation message from occupant '{}' to room '{}'.", packet.getFrom(), room.getName());
        try
        {
            final Element userInfo = packet.getChildElement("x", "http://jabber.org/protocol/muc#user");

            // Try to keep the list of extensions sent together with the message invitation. These extensions will be sent to the invitees.
            final List<Element> extensions = new ArrayList<>(packet.getElement().elements());
            extensions.remove(userInfo);

            // Send invitations to invitees
            final Iterator<Element> it = userInfo.elementIterator("invite");
            while ( it.hasNext() )
            {
                Element info = it.next();
                JID jid = new JID(info.attributeValue("to"));

                // Add the user as a member of the room if the room is members only
                if (room.isMembersOnly())
                {
                    room.addMember(jid, null, preExistingRole);
                }

                // Send the invitation to the invitee
                room.sendInvitation(jid, info.elementTextTrim("reason"), preExistingRole, extensions);
            }
        }
        catch ( ForbiddenException e )
        {
            Log.debug("Rejecting invitation message from occupant '{}' in room '{}': Invitations are not allowed, or occupant is not allowed to modify the member list.", packet.getFrom(), room.getName(), e);
            sendErrorPacket(packet, PacketError.Condition.forbidden, "This room disallows invitations to be sent, or you're not allowed to modify the member list of this room.");
        }
        catch ( ConflictException e )
        {
            Log.debug("Rejecting invitation message from occupant '{}' in room '{}'.", packet.getFrom(), room.getName(), e);
            sendErrorPacket(packet, PacketError.Condition.conflict, "An unexpected exception occurred."); // TODO Is this code reachable?
        }
        catch ( CannotBeInvitedException e )
        {
            Log.debug("Rejecting invitation message from occupant '{}' in room '{}': The user being invited does not have access to the room.", packet.getFrom(), room.getName(), e);
            sendErrorPacket(packet, PacketError.Condition.not_acceptable, "The user being invited does not have access to the room.");
        }
    }

    /**
     * Process a declination of a room-invitation message sent by an occupant of the room.
     *
     * @param packet          The stanza to process
     * @param room            The room that the stanza was addressed to.
     */
    private void processDecliningInvitationMessage(
        @Nonnull final Message packet,
        @Nonnull final MUCRoom room)
    {
        Log.trace("Processing an invite declination message from '{}' to room '{}'.", packet.getFrom(), room.getName());
        final Element info = packet.getChildElement("x", "http://jabber.org/protocol/muc#user").element("decline");
        room.sendInvitationRejection(new JID(info.attributeValue("to")),
            info.elementTextTrim("reason"), packet.getFrom());
    }

    /**
     * Processes an IQ stanza.
     *
     * @param packet          The stanza to route
     * @param room            The room that the stanza was addressed to.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza, if any.
     */
    private void process(
        @Nonnull final IQ packet,
        @Nullable final MUCRoom room,
        @Nullable final MUCRole preExistingRole )
    {
        // Packets to a specific node/group/room
        if ( preExistingRole == null || room == null)
        {
            Log.debug("Ignoring stanza received from a non-occupant of a room (room might not even exist): {}", packet.toXML());
            if ( packet.isRequest() )
            {
                // If a non-occupant sends a disco to an address of the form <room@service/nick>, a MUC service MUST
                // return a <bad-request/> error. http://xmpp.org/extensions/xep-0045.html#disco-occupant
                sendErrorPacket(packet, PacketError.Condition.bad_request, "You are not an occupant of this room.");
            }
            return;
        }

        if ( packet.isResponse() )
        {
            // Only process IQ result packet if it's a private packet sent to another room occupant
            if ( packet.getTo().getResource() != null )
            {
                try
                {
                    // User is sending an IQ result packet to another room occupant
                    room.sendPrivatePacket(packet, preExistingRole);
                }
                catch ( NotFoundException | ForbiddenException e )
                {
                    // Do nothing. No error will be sent to the sender of the IQ result packet
                    Log.debug("Silently ignoring an IQ response sent to the room as a private message that caused an exception while being processed: {}", packet.toXML(), e);
                }
            }
            else
            {
                Log.trace("Silently ignoring an IQ response sent to the room, but not as a private message: {}", packet.toXML());
            }
        }
        else
        {
            // Check and reject conflicting packets with conflicting roles In other words, another user already has this nickname
            if ( !preExistingRole.getUserAddress().equals(packet.getFrom()) )
            {
                Log.debug("Rejecting conflicting stanza with conflicting roles: {}", packet.toXML());
                sendErrorPacket(packet, PacketError.Condition.conflict, "Another user uses this nickname.");
                return;
            }

            try
            {
                // TODO Analyze if it is correct for these first two blocks to be processed without evaluating if they're addressed to the room or if they're a PM.
                Element query = packet.getElement().element("query");
                if ( query != null && "http://jabber.org/protocol/muc#owner".equals(query.getNamespaceURI()) )
                {
                    room.getIQOwnerHandler().handleIQ(packet, preExistingRole);
                }
                else if ( query != null && "http://jabber.org/protocol/muc#admin".equals(query.getNamespaceURI()) )
                {
                    room.getIQAdminHandler().handleIQ(packet, preExistingRole);
                }
                else
                {
                    final String toNickname = packet.getTo().getResource();
                    if ( toNickname != null )
                    {
                        // User is sending to a room occupant.
                        final boolean selfPingEnabled = JiveGlobals.getBooleanProperty("xmpp.muc.self-ping.enabled", true);
                        if ( selfPingEnabled && toNickname.equals(preExistingRole.getNickname()) && packet.isRequest()
                            && packet.getElement().element(QName.get(IQPingHandler.ELEMENT_NAME, IQPingHandler.NAMESPACE)) != null )
                        {
                            Log.trace("User '{}' is sending an IQ 'ping' to itself. See XEP-0410: MUC Self-Ping (Schrödinger's Chat).", packet.getFrom());
                            XMPPServer.getInstance().getPacketRouter().route(IQ.createResultIQ(packet));
                        }
                        else
                        {
                            Log.trace("User '{}' is sending an IQ stanza to another room occupant (as a PM) with nickname: '{}'.", packet.getFrom(), toNickname);
                            room.sendPrivatePacket(packet, preExistingRole);
                        }
                    }
                    else
                    {
                        Log.debug("An IQ request was addressed to the MUC room '{}' which cannot answer it: {}", room.getName(), packet.toXML());
                        sendErrorPacket(packet, PacketError.Condition.bad_request, "IQ request cannot be processed by the MUC room itself.");
                    }
                }
            }
            catch ( NotAcceptableException e )
            {
                Log.debug("Unable to process IQ stanza: room requires a password, but none was supplied.", e);
                sendErrorPacket(packet, PacketError.Condition.not_acceptable, "Room requires a password, but none was supplied.");
            }
            catch ( ForbiddenException e )
            {
                Log.debug("Unable to process IQ stanza: sender don't have authorization to perform the request.", e);
                sendErrorPacket(packet, PacketError.Condition.forbidden, "You don't have authorization to perform this request.");
            }
            catch ( NotFoundException e )
            {
                Log.debug("Unable to process IQ stanza: the intended recipient is not available.", e);
                sendErrorPacket(packet, PacketError.Condition.recipient_unavailable, "The intended recipient is not available.");
            }
            catch ( ConflictException e )
            {
                Log.debug("Unable to process IQ stanza: processing this request would leave the room in an invalid state (eg: without owners).", e);
                sendErrorPacket(packet, PacketError.Condition.conflict, "Processing this request would leave the room in an invalid state (eg: without owners).");
            }
            catch ( NotAllowedException e )
            {
                Log.debug("Unable to process IQ stanza: an owner or administrator cannot be banned from the room.", e);
                sendErrorPacket(packet, PacketError.Condition.not_allowed, "An owner or administrator cannot be banned from the room.");
            }
            catch ( CannotBeInvitedException e )
            {
                Log.debug("Unable to process IQ stanza: user being invited as a result of being added to a members-only room still does not have permission.", e);
                sendErrorPacket(packet, PacketError.Condition.not_acceptable, "User being invited as a result of being added to a members-only room still does not have permission.");
            }
            catch ( Exception e )
            {
                Log.error("An unexpected exception occurred while processing IQ stanza: {}", packet.toXML(), e);
                sendErrorPacket(packet, PacketError.Condition.internal_server_error, "An unexpected exception occurred while processing your request.");
            }
        }
    }

    /**
     * Process a Presence stanza.
     *
     * This method might be invoked for a room that does not yet exist (when the presence is a room-creation request).
     * This is why this method, unlike the process methods for Message and IQ stanza takes a <em>room name</em> argument
     * and returns the room that processed to request.
     *
     * @param packet          The stanza to process.
     * @param roomName        The name of the room that the stanza was addressed to.
     * @param room            The room that the stanza was addressed to, if it exists.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza, if any.
     * @return the room that handled the request
     */
    @Nullable
    private MUCRoom process(
        @Nonnull final Presence packet,
        @Nonnull final String roomName,
        @Nullable final MUCRoom room,
        @Nullable final MUCRole preExistingRole )
    {
        final Element mucInfo = packet.getChildElement("x", "http://jabber.org/protocol/muc"); // only sent in initial presence
        final String nickname = packet.getTo().getResource() == null
            || packet.getTo().getResource().trim().isEmpty() ? null
            : packet.getTo().getResource().trim();

        if ( preExistingRole == null && Presence.Type.unavailable == packet.getType() ) {
            Log.debug("Silently ignoring user '{}' leaving a room that it has no role in '{}' (was the room just destroyed)?", packet.getFrom(), roomName);
            return null;
        }

        if ( preExistingRole == null || mucInfo != null )
        {
            // If we're not already in a room (role == null), we either are joining it or it's not properly addressed and we drop it silently.
            // Alternative is that mucInfo is not null, in which case the client thinks it isn't in the room, so we should join anyway.
            return processRoomJoinRequest(packet, roomName, room, nickname);
        }
        else
        {
            // Check and reject conflicting packets with conflicting roles
            // In other words, another user already has this nickname
            if ( !preExistingRole.getUserAddress().equals(packet.getFrom()) )
            {
                Log.debug("Rejecting conflicting stanza with conflicting roles: {}", packet.toXML());
                sendErrorPacket(packet, PacketError.Condition.conflict, "Another user uses this nickname.");
                return room;
            }

            if (room == null) {
                if (Presence.Type.unavailable == packet.getType()) {
                    Log.debug("Silently ignoring user '{}' leaving a non-existing room '{}' (was the room just destroyed)?", packet.getFrom(), roomName);
                } else {
                    Log.warn("Unable to process presence update from user '{}' to a non-existing room: {}", packet.getFrom(), roomName);
                }
                return null;
            }
            try
            {
                if ( nickname != null && !preExistingRole.getNickname().equalsIgnoreCase(nickname) && Presence.Type.unavailable != packet.getType() )
                {
                    // Occupant has changed his nickname. Send two presences to each room occupant.
                    processNickNameChange(packet, room, preExistingRole, nickname);
                }
                else
                {
                    processPresenceUpdate(packet, room, preExistingRole);
                }
            }
            catch ( Exception e )
            {
                Log.error(LocaleUtils.getLocalizedString("admin.error"), e);
            }
            return room;
        }
    }

    /**
     * Process a request to join a room.
     *
     * This method might be invoked for a room that does not yet exist (when the presence is a room-creation request).
     *
     * @param packet   The stanza representing the nickname-change request.
     * @param roomName The name of the room that the stanza was addressed to.
     * @param room     The room that the stanza was addressed to, if it exists.
     * @param nickname The requested nickname.
     * @return the room that handled the request
     */
    private MUCRoom processRoomJoinRequest(
        @Nonnull final Presence packet,
        @Nonnull final String roomName,
        @Nullable MUCRoom room,
        @Nullable String nickname )
    {
        Log.trace("Processing join request from '{}' for room '{}'", packet.getFrom(), roomName);

        if ( nickname == null )
        {
            Log.debug("Request from '{}' to join room '{}' rejected: request did not specify a nickname", packet.getFrom(), roomName);

            // A resource is required in order to join a room http://xmpp.org/extensions/xep-0045.html#enter
            // If the user does not specify a room nickname (note the bare JID on the 'from' address in the following example), the service MUST return a <jid-malformed/> error
            if ( packet.getType() != Presence.Type.error )
            {
                sendErrorPacket(packet, PacketError.Condition.jid_malformed, "A nickname (resource-part) is required in order to join a room.");
            }
            return null;
        }

        if ( !packet.isAvailable() )
        {
            Log.debug("Request from '{}' to join room '{}' rejected: request unexpectedly provided a presence stanza of type '{}'. Expected none.", packet.getFrom(), roomName, packet.getType());
            if ( packet.getType() != Presence.Type.error )
            {
                sendErrorPacket(packet, PacketError.Condition.unexpected_request, "Unexpected stanza type: " + packet.getType());
            }
            return null;
        }

        if (room == null) {
            try {
                // Create the room
                final MultiUserChatService service = getChatService();
                if (service == null) {
                    throw new IllegalStateException("Unable to find MUC service '" + serviceName + "' to get or create room '" + roomName + "' for " + packet.getFrom());
                }
                room = service.getChatRoom(roomName, packet.getFrom());
            } catch (NotAllowedException e) {
                Log.debug("Request from '{}' to join room '{}' rejected: user does not have permission to create a new room.", packet.getFrom(), roomName, e);
                sendErrorPacket(packet, PacketError.Condition.not_allowed, "You do not have permission to create a new room.");
                return null;
            }
        }

        try
        {
            // User must support MUC in order to create a room
            HistoryRequest historyRequest = null;
            String password = null;

            // Check for password & requested history if client supports MUC
            final Element mucInfo = packet.getChildElement("x", "http://jabber.org/protocol/muc");
            if ( mucInfo != null )
            {
                password = mucInfo.elementTextTrim("password");
                if ( mucInfo.element("history") != null )
                {
                    historyRequest = new HistoryRequest(mucInfo);
                }
            }

            // The user joins the room
            final MUCRole role = room.joinRoom(nickname,
                password,
                historyRequest,
                this,
                packet.createCopy());

            // If the client that created the room is non-MUC compliant then
            // unlock the room thus creating an "instant" room
            if ( mucInfo == null && room.isLocked() && !room.isManuallyLocked() )
            {
                room.unlock(role);
            }
        }
        catch ( UnauthorizedException e )
        {
            Log.debug("Request from '{}' to join room '{}' rejected: user not authorized to create or join the room.", packet.getFrom(), roomName, e);
            sendErrorPacket(packet, PacketError.Condition.not_authorized, "You're not authorized to create or join the room.");
        }
        catch ( ServiceUnavailableException e )
        {
            Log.debug("Request from '{}' to join room '{}' rejected: the maximum number of users of the room has been reached.", packet.getFrom(), roomName, e);
            sendErrorPacket(packet, PacketError.Condition.service_unavailable, "The maximum number of users of the room has been reached.");
        }
        catch ( UserAlreadyExistsException | ConflictException e )
        {
            Log.debug("Request from '{}' to join room '{}' rejected: the requested nickname '{}' is being used by someone else in the room.", packet.getFrom(), roomName, nickname, e);
            sendErrorPacket(packet, PacketError.Condition.conflict, "The nickname that is being used is used by someone else.");
        }
        catch ( RoomLockedException e )
        {
            // If a user attempts to enter a room while it is "locked" (i.e., before the room creator provides an initial configuration and therefore before the room officially exists), the service MUST refuse entry and return an <item-not-found/> error to the user
            Log.debug("Request from '{}' to join room '{}' rejected: room is locked.", packet.getFrom(), roomName, e);
            sendErrorPacket(packet, PacketError.Condition.item_not_found, "This room is locked (it might not have been configured yet).");
        }
        catch ( ForbiddenException e )
        {
            Log.debug("Request from '{}' to join room '{}' rejected: user not authorized join the room.", packet.getFrom(), roomName, e);
            sendErrorPacket(packet, PacketError.Condition.forbidden, "You're not allowed to join this room.");
        }
        catch ( RegistrationRequiredException e )
        {
            Log.debug("Request from '{}' to join room '{}' rejected: room is member-only, user is not a member.", packet.getFrom(), roomName, e);
            sendErrorPacket(packet, PacketError.Condition.registration_required, "This is a member-only room. Membership is required.");
        }
        catch ( NotAcceptableException e )
        {
            Log.debug("Request from '{}' to join room '{}' rejected: user attempts to use nickname '{}' which is different from the reserved nickname.", packet.getFrom(), roomName, nickname, e);
            sendErrorPacket(packet, PacketError.Condition.not_acceptable, "You're trying to join with a nickname different than the reserved nickname.");
        }
        return room;
    }

    /**
     * Process a presence status update for a user.
     *
     * @param packet          The stanza to process
     * @param room            The room that the stanza was addressed to.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza.
     */
    private void processPresenceUpdate(
        @Nonnull final Presence packet,
        @Nonnull final MUCRoom room,
        @Nonnull final MUCRole preExistingRole )
    {
        if ( Presence.Type.unavailable == packet.getType() )
        {
            Log.trace("Occupant '{}' of room '{}' is leaving.", preExistingRole.getUserAddress(), room.getName());
            // TODO Consider that different nodes can be creating and processing this presence at the same time (when remote node went down)
            preExistingRole.setPresence(packet);
            room.leaveRoom(preExistingRole);
        }
        else
        {
            Log.trace("Occupant '{}' of room '{}' changed its availability status.", preExistingRole.getUserAddress(), room.getName());
            room.presenceUpdated(preExistingRole, packet);
        }
    }

    /**
     * Process a request to change a nickname.
     *
     * @param packet          The stanza representing the nickname-change request.
     * @param room            The room that the stanza was addressed to.
     * @param preExistingRole The role of this user in the addressed room prior to processing of this stanza.
     * @param nickname        The requested nickname.
     */
    private void processNickNameChange(
        @Nonnull final Presence packet,
        @Nonnull final MUCRoom room,
        @Nonnull final MUCRole preExistingRole,
        @Nonnull String nickname )
        throws UserNotFoundException
    {
        Log.trace("Occupant '{}' of room '{}' tries to change its nickname to '{}'.", preExistingRole.getUserAddress(), room.getName(), nickname);

        if ( room.getOccupantsByBareJID(packet.getFrom().asBareJID()).size() > 1 )
        {
            Log.trace("Nickname change request denied: requestor '{}' is not an occupant of the room.", packet.getFrom().asBareJID());
            sendErrorPacket(packet, PacketError.Condition.not_acceptable, "You are not an occupant of this chatroom.");
            return;
        }

        if ( !room.canChangeNickname() )
        {
            Log.trace("Nickname change request denied: Room configuration does not allow nickname changes.");
            sendErrorPacket(packet, PacketError.Condition.not_acceptable, "Chatroom does not allow nickname changes.");
            return;
        }

        if ( room.hasOccupant(nickname) )
        {
            Log.trace("Nickname change request denied: the requested nickname '{}' is used by another occupant of the room.", nickname);
            sendErrorPacket(packet, PacketError.Condition.conflict, "This nickname is taken.");
            return;
        }

        // Send "unavailable" presence for the old nickname
        final Presence presence = preExistingRole.getPresence().createCopy();
        // Switch the presence to OFFLINE
        presence.setType(Presence.Type.unavailable);
        presence.setStatus(null);
        // Add the new nickname and status 303 as properties
        final Element frag = presence.getChildElement("x", "http://jabber.org/protocol/muc#user");
        frag.element("item").addAttribute("nick", nickname);
        frag.addElement("status").addAttribute("code", "303");
        room.send(presence, preExistingRole);

        // Send availability presence for the new nickname
        final String oldNick = preExistingRole.getNickname();
        room.nicknameChanged(preExistingRole, packet, oldNick, nickname);
    }

    public static boolean isDeliveryRelatedErrorResponse(@Nonnull final Packet stanza)
    {
        final Collection<PacketError.Condition> deliveryRelatedErrorConditions = Arrays.asList(
            PacketError.Condition.gone,
            PacketError.Condition.item_not_found,
            PacketError.Condition.recipient_unavailable,
            PacketError.Condition.redirect,
            PacketError.Condition.remote_server_not_found,
            PacketError.Condition.remote_server_timeout
        );

        final PacketError error = stanza.getError();
        return error != null && deliveryRelatedErrorConditions.contains(error.getCondition());
    }

    /**
     * Returns the id of the node that is hosting the room occupant.
     *
     * @return the id of the node that is hosting the room occupant.
     */
    public NodeID getNodeID() {
        return XMPPServer.getInstance().getNodeID();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MUCUser mucUser = (MUCUser) o;
        return Objects.equals(serviceName, mucUser.serviceName) && Objects.equals(realjid, mucUser.realjid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serviceName, realjid);
    }

    @Override
    public int getCachedSize() throws CannotCalculateSizeException {
        int size = CacheSizes.sizeOfObject(); // overhead of object.
        size += CacheSizes.sizeOfString(serviceName);
        size += CacheSizes.sizeOfAnything(realjid);
        size += CacheSizes.sizeOfCollection(roomNames);
        size += CacheSizes.sizeOfObject() + CacheSizes.sizeOfLong() + CacheSizes.sizeOfInt(); // lastPacketTime
        return size;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        ExternalizableUtil.getInstance().writeSafeUTF(out, serviceName);
        ExternalizableUtil.getInstance().writeSafeUTF(out, realjid.toString());
        ExternalizableUtil.getInstance().writeSerializableCollection(out, roomNames);
        ExternalizableUtil.getInstance().writeSerializable(out, lastPacketTime);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        serviceName = ExternalizableUtil.getInstance().readSafeUTF(in);
        realjid = new JID(ExternalizableUtil.getInstance().readSafeUTF(in), false);
        roomNames = new HashSet<>();
        ExternalizableUtil.getInstance().readSerializableCollection(in, roomNames, this.getClass().getClassLoader());
        lastPacketTime = (Instant) ExternalizableUtil.getInstance().readSerializable(in);
    }

    @Override
    public String toString() {
        return "MUCUser{" +
            "serviceName='" + serviceName + '\'' +
            ", realjid=" + realjid +
            ", rooms=" + roomNames +
            ", lastPacketTime=" + lastPacketTime +
            '}';
    }
}

