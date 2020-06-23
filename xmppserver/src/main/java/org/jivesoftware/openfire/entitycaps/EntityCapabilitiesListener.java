/*
 * Copyright (C) 2020 Ignite Realtime Foundation. All rights reserved.
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
package org.jivesoftware.openfire.entitycaps;

import org.xmpp.packet.JID;

import javax.annotation.Nonnull;

/**
 * Interface to listen for entity capabilities events. Use methods in {@link EntityCapabilitiesManager} to register
 * for events.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 * @see <a href="https://xmpp.org/extensions/xep-0115.html>XEP-0115: Entity Capabilities</a>
 */
public interface EntityCapabilitiesListener
{
    /**
     * Invoked when a change was detected in the capabilities of a particular entity.
     *
     * @param entity The entity for which CAPS changed.
     * @param updatedEntityCapabilities The updated capabilities.
     */
    void entityCapabilitiesChanged( @Nonnull JID entity, @Nonnull EntityCapabilities updatedEntityCapabilities );
}
