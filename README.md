# PlugAndPray: UPnP tool

The idea was to create a "universal" tool to have fun with UPnP enabled devices, which could run on vanilla Python (no SOAPpy, no other unsupported crap).

# Project state

This is in deep alpha -- that is, it hardly works.

That said, this is what we have at the moment:

* Discovery of UPnP capable devices via multicast SSDP
* Unicast SSDP query
* UPnP related set of classes allowing to parse device and service descriptors
* Action invocation (somewhat rudimentary at the point)
 
This is what we don't have yet:

* Proper command line handling
* Handling of errors and corner cases
