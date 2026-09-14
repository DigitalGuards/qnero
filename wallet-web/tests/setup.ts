/**
 * What the unit tests need that Node does not have.
 *
 * `fake-indexeddb` for the store, and `crypto` is already global in Node 22.
 * Nothing here touches a network or a chain: the chain tests drive the sync
 * rules through a recording transport, which is the point of that seam.
 */

import 'fake-indexeddb/auto';
