# Working with AppData

> [!IMPORTANT]
> Currently this functionality is behind the `extensions-draft-08` feature. 

The [MLS Extensions] draft specifies a new mechanism to encode application data in the group state.
When using custom extensions for this purpose, every update message contains the full new state,
for example in a GroupContextExtensionProposal.
The new mechanism allows updating the application data in an application-defined way.
This is very flexible an allows to implement a wide range of diff-style approaches.
However, it puts more burden on the application, since it needs to validate and process the updates
itself to produce the new state.

> [!NOTE]
> The extensions draft specifies ComponentIDs to be 32 bit, but after publishing this was reduced
> to 16 bit. More context here:
>
> TODO

Let us create a group with two parties that has AppDataUpdate as a required capability.

Just for the example, our component is a counter, and the updates contain either a signal to increment or
to decrement the counter. Incrementing a counter that hasn't been set yet sets it to 1, and decrementing below zero is invalid. A The ComponentID is 0xf042.

TODO: add book code that
- defines the types and methods for the counter in the example
- creates two parties alice and bob
- alice creates a new group with AppDataUpdate proposals in required capabilities
- (do we also need the AppDataDictionaryExtension?)
- alice invites bob and merges
- bob joins

Let us now update the AppData for one of the components. Both parties process the commit to assemble
the new state.

TODO: add book code that 
- alice creates a commit that updates the group state.
  - contains 3 proposals for incrementing the counter.
- both process the message and merge.
- we check that both are still in the same state (e.g. compare confirmation_tag, send&recv message, ...)

