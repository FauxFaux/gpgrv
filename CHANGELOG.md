## 0.4.1

 * add parse (but not verify) support for newer key formats
 * dep bumps


## 0.4.0

 * fix handling of trailing whitespace
 * new edition; no more msrv due to e.g. clap
 * bump deps


## 0.3.0

 * switch to `anyhow` for errors, raising msrv


## 0.2.2

 * support for armoured keys (@lutostag)


## 0.2.0

 * Unify message formats, and support binary doc
     parsing.
 * Previous use of `verify_clearsign_armour` are now
     `verify_message`, which detects armoured or binary
      data streams. `verify_detached` can read
     detached signatures.
 * Other functions have been eaten by `read_doc`.
