# MLS Delivery Service Tools

This library provides tools that can be convenient for an MLS Delivery Service
(DS). We do not cover the actual delivery mechanics, but instead on more
advanced functions where the DS needs to be aware of the internals of the MLS
protocol.

For example, it is sometimes useful for the DS to maintain a view of a group's
ratchet tree based on seeing the group's Commits (sent as PublicMessage).  To do
this, the DS needs to parse commits and know how to apply them to the tree.
The `TreeFollower` class provided in this library implements this functionality.
