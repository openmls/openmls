import * as wasm from "openmls";

window.wasm =wasm;

let alice = new wasm.Identity("alice");
let bob = new wasm.Identity("bob");

let chess_club_alice = wasm.Group.create_new(alice, "chess club");

let bob_key_pkg = bob.key_package();

let add_msgs = chess_club_alice.propose_and_commit_add(alice, bob_key_pkg);

let ratchet_tree = chess_club_alice.export_ratchet_tree();

let chess_club_bob = wasm.Group.join(add_msgs.welcome, ratchet_tree);

let bob_exported_key = chess_club_bob.export_key("chess_key", UInt8Array([0x30], 32));
let alice_exported_key = chess_club_alice.export_key("chess_key", UInt8Array([0x30], 32));

window.foo = {
  alice, bob, chess_club_alice, bob_key_pkg , add_msgs, ratchet_tree, chess_club_bob, bob_exported_key, alice_exported_key
};

wasm.greet();
