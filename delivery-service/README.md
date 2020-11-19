# MLS Proof-of-Concept Delivery Service

This is a proof-of-concept for an MLS delivery service. It currently supports
the following operations:

* Registering Clients via a POST request to `/clients/register`
* Listing Clients via a GET request to `/clients/list`
* GetClientInfo via a GET request to `/clients/get`
* CreateGroup via a POST request to `/groups/new`
* SendMessage via a POST request to `/msg/send`
