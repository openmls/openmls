# WebAssembly

OpenMLS can be built for WebAssembly. However, it does require two features that WebAssembly itself does not provide: access to secure randomness and the current time. Currently, this means that it can only run in a runtime that provides common JavaScript APIs (e.g. in the browser or node.js), accessed through the `web_sys` crate.
You can enable the `js` feature on the `openmls` crate to signal that the APIs are available.
