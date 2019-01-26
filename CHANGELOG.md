## 0.2.0

 * Unify message formats, and support binary doc
     parsing.
 * Previous use of `verify_clearsign_armour` are now
     `verify_message`, which detects armoured or binary
      data streams. `verify_detached` can read
     detached signatures.
 * Other functions have been eaten by `read_doc`.
 