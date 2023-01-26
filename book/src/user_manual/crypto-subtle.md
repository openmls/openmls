# crypto-subtle feature

This feature of the OpenMLS crate allows importing and exporting private signature keys that can be used with credentials.

⚠️ Note that no checks are performed on the keys. Use this feature at your own risk. If you create a credential from an existing key
or export key material, you are responsible for deleting that key. If that key is kept outside OpenMLS,
updating a leaf will not be enough to achieve Forward Secrecy/Post-compromise Security.
