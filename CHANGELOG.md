## 0.2.0

 * Unify message formats, and support binary doc
     parsing (to some extent, messages are in packets
     we can't read yet).
 * Previous use of e.g. `verify_clearsign_armour` are now
     simply `verify_message`. `parse_clearsign_armour` (i.e.
     unpack a message without verifying it) is now inside `read_doc`.
