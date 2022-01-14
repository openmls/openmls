# Tree Rewrite Project

![](https://img.shields.io/badge/status-wip-orange.svg?style=for-the-badge)

## TreeSync

TreeSync is a tree structure that keeps public data in a left-balanced binary
tree structure and relies on a KeyStore to store private data. Not every node
has to contain data. A node not containing data is considered blank. The
TreeSyncNode API determines how TreeSync interacts with the data it stores.

![TreeSync Architecture](./static/treesync_api.svg)

#### Node Indexing

The current MLS spec explicitly relies on leaf- or node indices specific to the
array-representation of a tree to indicate individual nodes. Thus, to keep it
simple, this draft of a TreeSync API relies on the same indices.

In an actual implementation, we might have to translate from the array-specific
indices to whatever is used by the actual binary tree implementation underneath
`TreeSync`.

### TreeSyncNode API

TreeSync relies on the `TreeSyncNode` to represent the layer of abstraction
below it.

```rust
trait TreeSyncNode {
    /// Return the value of the node relevant for the parent hash and tree hash.
    /// In case of MLS, this would be the node's HPKEPublicKey. TreeSync
    /// can then gather everything necessary to build the `ParentHashInput`,
    /// `LeafNodeHashInput` and `ParentNodeTreeHashInput` structs for a given node.
    fn node_content(&self) -> &[u8] {}

    /// Get the list of unmerged leaves.
    fn unmerged_leaves(&self) -> &[LeafIndex] {}

    /// Clear the list of unmerged leaves.
    fn clear_unmerged_leaves(&mut self) {}

    /// Add a `LeafIndex` to the node's list of unmerged leaves.
    fn add_unmerged_leaf(&mut self, LeafIndex) {}

    /// Set the parent hash value of this node.
    fn set_parent_hash(&mut self, Vec<u8>) {}

    /// Get the parent hash value of this node.
    fn parent_hash(&self) -> &[u8] {}

    /// Set the tree hash value for the given node.
    /// This assuming that the node caches the tree hash.
    fn set_tree_hash(&mut self, Vec<u8>) {}

    /// Get the tree hash value for the given node.
    fn tree_hash(&self) -> &[u8] {}

    /// Verify the signature on a given leaf node. Returns an
    /// error if called on a non-leaf node.
    fn verify(&self) -> Result<bool, TreeSyncNodeError> {}
}
```

### TreeSync API

Note, that a majority of the tree operations are performed on TreeSyncDiffs (see
below).

```rust
struct TreeSync<Node: TreeSyncNode, KeyStore: TreeSyncKeyStore> {
    FLBBinaryTree<Option<Node>>
}

impl<Node: TreeSyncNode, KeyStore: TreeSyncKeyStore> TreeSync<Node, KeyStore> {
    /// Return the tree hash of the root node.
    fn tree_hash(&self) -> Vec<u8> {}

    /// Verify the parent hash of every parent node in the tree.
    fn verify_parent_hashes -> Result<(), TreeSyncError> {}

    /// Merge the given diff into the `TreeSync` instance. This operation
    /// re-computes all necessary tree hashes.
    /// Note, that the private values corresponding to the ones in the
    /// TreeSync should be committed at the same time.
    fn merge_diff(&mut self, tree_sync_diff: TreeSyncDiff) -> Result<(), TreeSyncError> {}

    /// Create an empty diff based on this TreeSync instance all operations
    /// are created based on an initial, empty diff.
    fn empty_diff(&self) -> TreeSyncDiff {}
}
```

### TreeSyncDiffs

```rust
struct<Node: TreeSyncNode> TreeSyncDiff<Node> {
    nodes: HashMap<NodeIndex,Option<Node>>,
}

impl<Node: TreeSyncNode, KeyStore: TreeSyncKeyStore> TreeSyncDiff<Node> {
    /// Update a leaf node and blank the nodes in the updated leaf's direct path.
    fn update_leaf(&mut self, leaf_node: Node, leaf_index: LeafIndex) -> TreeSyncDiff {}

    /// Adds a new leaf to the tree either by filling a blank leaf or by creating a new leaf,
    /// inserting intermediate blanks as necessary. This also adds the leaf_index of the new
    /// leaf to the `unmerged_leaves` state of the parent nodes in its direct path.
    fn add_leaf(&mut self, leaf_node: Node) -> Result<TreeSyncDiff, TreeSyncError> {}

    /// Remove a group member by blanking the target leaf and its direct path.
    fn remove_leaf(&mut self, leaf_index: LeafIndex) -> Result<TreeSyncDiff, TreeSyncError> {}

    /// Process a given update path, consisting of a vector of `Node`. This
    /// function
    /// * replaces the nodes in the direct path of the given `leaf_node` with the
    ///   the ones in `path` and
    /// * computes the `parent_hash` of all nodes in the path and compares it to the one in
    ///   the `leaf_node`.
    fn update_path(&mut self, leaf_node: Node, path: Vec<Node>) -> TreeSyncDiff {}

    /// Compute the tree hash of the TreeSync instance we would get when merging the diff.
    fn tree_hash(&self) -> Vec<u8> {}
}
```

### TreeSync Usage Example

```rust
/// This function demonstrates how TreeSync could be used to manage a tree and could be
/// used in create_commit to create a provisional tree and the
/// corresponding values (tree_hash, commit_secret, etc).
/// It returns the diff resulting from the operations applied to the TreeSync instance,
/// as well as the vector of `NodeSeed`s that can then be encrypted using TreeKEM.
/// Note, that the application with apply_commit is slightly asymmetrical, as we would potentially have
/// to pass in an additional `path` for TreeSync to apply.
fn apply_proposals(&self, key_store: &KeyStore, proposal_list: Vec<Proposal>) -> Result<(TreeSyncDiff), ApplyProposalsError>{
    // ...
    // as Proposals are not generic, we have to translate them
    // individually to TreeSync operations
    // the assumption here is that the list of proposals is already
    // ordered by type and order as per commit
    let mut path_required = false;
    let mut my_new_key_package = None;
    let mut diff = self.tree_sync.empty_diff();
    for proposal in &proposal_list {
        match proposal {
          Update(key_package) => {
              // If we process an update, we need to include a path in the end
              path_required = true;
              // We process self updates later using the update_path function
              if key_package.identity() != &self.identity {
                  diff.update_leaf(key_package.into())
              } else {
                  my_new_key_package = Some(key_package)
              }
          },
          Add(key_package) => diff.add(TreeSyncNode::from(key_package)),
          // It's not clear yet how to expose "identity" to TreeSync.
          Remove(leaf_index) => {
              // If we process a remove, we need to include a path in the end
              path_required = true;
              diff.remove(leaf_index),
          }
        };
    }


    // If we want to create a path and/or one of the updates was a
    // self-update.
    if path_required || my_new_key_package.is_some() {
        // a path is required, but there's no explicit update, generate a new key_package
        if my_new_key_package.is_none() {
            my_new_key_package = key_store.generate_key_package_bundle(...);
        }
        // We assume that this function gives us the path based on the leaf_secret of the
        // key package bundle, which is in the key store.
        let (path, path_secrets) = create_path(&key_store, &my_new_key_package)?;
        // The private values generated in the process are put into the key store
        // This will compute the path secret and set it in the new leaf node.
        diff.update_path(TreeSyncLeafNode(my_new_key_package.unwrap()), path)?;
    } else {
        diff
    }

    // We can now call TreeKEM and encrypt the `path_secrets` (see below).
}
```

## TreeKEM Trait

TreeKEM would take one of the "node seed" discussed above and encrypt/decrypt
it. For encryption/decryption it would need access to a TreeSync instance, where
`Node` implements `TreeKemNode`, which in turn provides the functions that
TreeKEM needs. In particular, it would have to provide access to the public keys
of each node.

```rust
trait TreeKemNode<KeyStore: TreeSyncKeyStore> {
    /// Encrypt a given plaintext to the node's public key.
    fn encrypt(&self, plaintext: &[u8]) -> HpkeCiphertext {}

    /// Decrypt a given ciphertext using the secret key corresponding to the node.
    fn decrypt(&self, key_store: &KeyStore, ciphertext: &HpkeCiphertext) -> Vec<u8> {}
}

trait<KeyStore: TreeSyncKeyStore> TreeKem<KeyStore> {
    /// Create an UpdatePath by encrypting a vector of `NodeSeed`s
    /// to the direct path of our own leaf.
    fn encrypt_path(&self, path: Vec<NodeSeed>) -> Result<UpdatePath, TreeKemError> {}

    /// Decrypt an UpdatePath, returning the `NodeSeed` and the vector of `Node`s.
    fn decrypt_path(&self, key_store: KeyStore, update_path: UpdatePath) -> Result<(NodeSeed, Vec<Node>), TreeKemError> {}
}

```

Questions:
* Should we allow TreeKEM to know about KeyPackages or do we draw the
  abstraction line at public keys? It needs to know about KeyPackages to be able
  to return an UpdatePath. Otherwise it would be a vector of UpdatePathNode.

TODO: Create a KeyStore API for TreeKem. See https://github.com/franziskuskiefer/key-store-rs/blob/main/src/traits.rs


### KeyStore API (old API for TreeSync)

TreeSync requires a place in which to store secrets and private keys. In
particular, it should store:
* Pairs of `(PrivateState, NodeSeed)` indexed by `PrivateStateHandle` for updates to one's own leaf node. These
  are independent of a given group and get consumed when used.
* A `NodeSeed`, which represents the `CommitSecret` in MLS-terms.
* A number of `PrivateState`, representing the private values of the nodes in
  one's own direct path, indexed by Node indices. This includes the
  `PrivateState` of the leaf.
* A temporary `Vec<PrivateState>`, for the private part of a provisional
  TreeSync state.
* A temporary `NodeSeed`, for the private part of a provisional TreeSync state.

The individual get and erase functions allow the persistence of derivations of
the `NodeSeed` before deleting it.

```rust
trait TreeSyncKeyStore<Node: TreeSyncNode> {
    /// Store a pair of `Node::NodeSeed` and `Node::PrivateState` corresponding to a
    /// `Node` meant to be used as a leaf node in a future update. Note, that
    /// the `Node::NodeSeed` will only be used if we commit the update ourselves.
    fn store_leaf_node_private_state(&mut self, node_seed: Node::NodeSeed, private_values: Node::PrivateState) {}

    /// Take a pair of `Node::NodeSeed` and `Node::PrivateState` corresponding to a
    /// `Node::PrivatStateHandle`, thereby removing it from the store.
    fn take_leaf_node_private_state(&mut self, handle: Node::PrivateStateHandle) -> Result<(Node::NodeSeed, Node:: PrivateState), KeyStoreError> {}

    /// Store the temporary `Vec<Node::PrivateState>` and `Node::NodeSeed`.
    fn store_temporary_private_states(&mut self, private_values: (Vec<Node::PrivateState>, Node::NodeSeed)) {}

    /// Commit to the current temporary `Vec<Node::PrivateState>` and `Node::NodeSeed`
    /// by using it to overwrite the corresponding non-temporary values.
    fn commit_to_temporary_values(&mut self) {}

    /// Get the `Node::NodeSeed`. Note, that it should be removed using
    /// `erase_node_seed` after it was used.
    fn node_seed(&self) -> Node::NodeSeed {}

    /// Get the `Node::NodeSeed`. Note, that it should be removed using
    /// `erase_node_seed` after it was used.
    fn erase_node_seed(&mut self) {}
}
```


## Binary Tree API

`TreeSync`, `TreeKEM` and `TreeDEM` rely on an underlying full, left-balenced
binary tree representation `FLBBinaryTree` to organise its data and to process
it.

As discussed above, the following binary tree API relies on the indices of an
array-based binary tree representation. While the binary tree implementation
needs to provide an interface based on these indices, it does not necessarily
need to organise the data in memory in the style of the array-representation.

```rust
trait FLBBinaryTree<Node> {
    /// Obtain a reference to the data contained in the `Node` at index `node_index`.
    /// Returns an error if the index is outside of the tree.
    fn node(&self, node_index: NodeIndex) -> Result<&Node, FLBBBinaryTreeError> {}

    /// Obtain a mutable reference to the data contained in the `Node` at index `node_index`.
    /// Returns an error if the index is outside of the tree.
    fn node_mut(&mut self, node_index: NodeIndex) -> Result<&mut Node, FLBBBinaryTreeError> {}

    /// Add two nodes to the right side of the tree. Nodes can only be
    /// added in pairs to keep the tree full.
    fn add(&mut self, node_1:Node , node_2: Node) -> Result<(), FLBBBinaryTreeError> {}

    /// Remove the two rightmost nodes of the tree.
    fn remove(&mut self) -> Result<(), FLBBBinaryTreeError> {}
}
```

## Open Questions/TODOs:

- [X] What's the `BinaryTree` API? (FK)
  * Added a secion on full, left-balanced BinaryTree API. It leaves a lot of
    functionality in `TreeSync`, but it keeps the interface simple and small.
- [ ] How do diffs work with the key store? (FK)
  * There's now a TreeSync specific KeyStore API that includes temporary values.
  - [X] Write an example of what kind of secrets we want to store and when, as
        well as what kind of secrets we want to delete and when.
  - [ ] Store secrets based on group + epoch.
  - [ ] Implement CRUD interface.
- [ ] What's the most efficient data structure for `TreeSyncDiff`? (FK)
  * If it's a vector, the elements should get a struct.
  * Initial idea is to make it a `HashMap<NodeIndex,TreeSyncNode>`
- [ ] Does any of these structs need internal mutability? (FK)
- [ ] Should there be shared functionality for diffs? (FK)
- [ ] `TreeSync` should have a cache for hashes. (FK)
  * The current design requires the underlying nodes to do the hashing.
    Not sure if that's the optimal approach.
- [ ] Design API for TreeDEM
- [ ] Rework Diff types to be abstract and independent of the binary tree implementation
  * We have the same argument here as for MLS. We need some way to address individual nodes
    and we use indices from the array-based representation for that. As long as the underlying
    binary tree maps that to the underlying memory model, it should work fine.
- [ ] Do we want persistence for diffs?
