# MLS Delivery Service

This is a proof-of-concept for an MLS delivery service that can be used for testing. It currently supports the following operations:

* Registering Clients via a POST request to `/clients/register`
* Listing Clients via a GET request to `/clients/list`
* Get a list of key packages of a client via a GET request to `/clients/get/{name}`
* Send an MLS group message via a POST request to `/send/message`
* Send a Welcome message via a POST request to `/send/welcome`
* Get a list of messages for a client via a GET request to `/recv/{name}`

Necessary message types are defined in the [ds-lib](../ds-lib/).
