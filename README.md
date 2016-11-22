# mender-stress-test-client
Mender stress test client

This mender client uses the existing mender client package to create many "fake" mender clients using Golang go routines.
This client successfully performs client authentication, and uses the backend API correctly, in order to emulate a device.

To run with default options:
`~/go/bin/mender-dummy -count <device count>`

pass the -h flag for all options.
