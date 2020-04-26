# Fully Collision-Resistant Chameleon-Hashes
This is a Rust implementation of fully collision resistant chameleon hash from [this paper](https://eprint.iacr.org/2020/403.pdf). 

## TODO etc.

This is currently work in progress and this list collects open TODOs and other things which came to mind during implementation.

- Wrap base point s.t. no direct access to ristretto required
- Abstract out groups
- Separate primitives into individual modules
- Error handling
- Serialization and deserialization
- Code documentation
- Make tuples with one element unnamed in dlog.rs