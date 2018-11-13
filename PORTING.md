The SAE module, `sae.c`, is OS-independent. The OS-specific portion
of this release is `<os>/meshd.c`. Porting SAE to a different OS requires
definition of a new meshd.c module for the new OS. Each `<os>/meshd.c`
must:

  1. manage a wireless interface-- set the ssid, set the band, set
     the channel, et cetera.
  2. receive beacons and authentication frames in an OS-specific
     manner. 
  3. be capable of sending authentication frames over the wireless
     interface. 

A generic service model, `service.[ch]`, is included to allow `<os>/meshd.c`
to manage socket interfaces and sae to manage timers. Replacement of
`service.[ch]` with a different service model should be trivial. 

`os_glue.h` defines the external API each `<os>/meshd.c` must have
to allow SAE to use to send frames over the air. These are:

  - `int meshd_write_mgmt(char *frame, int len, void *cookie)`

	To send a management frame over the air.

  - `void fin(unsigned short status, unsigned char *peer_mac, 
	      unsigned char *key, int keylen, void *cookie)`

	To obtain notification of termination of sae. The status
	is defined in ieee802_11.h and, if zero, a key will be
	returned for the specified MAC address.

	`<os>/meshd.c` must make a local copy of this key if it wants to
	manipulate it for any reason.

`sae.h` defines the routines each `<os>/meshd.c` must call to enable SAE
authentication.

  - `int sae_initialize(char *ssid, char *config_directory)`

	This must be called first, before any processing is done. It
	allows SAE to configure itself.

  - `int process_mgmt_frame(struct ieee80211_mgmt_frame *frame, int len, 
                           unsigned char *local_mac_addr, void *cookie);`

	Used to send beacons and authentiction frames to SAE for
    processing.  The cookie argument is passed back to the caller on all
    callbacks associated with this management frame (e.g. `meshd_write_mgmt()`,
    `fin()`).  It is mapped to associated with a given peer.

  - `void sae_read_config(int signal)`

	This is a helper routine that can be used to catch HUP, or
	`<os>/meshd.c` can catch HUP itself and call this routine
	if an `sa_handler(int)` action is not supported by the OS.

	It re-reads the SAE configuration without having to stop
	and re-start meshd.

  - `void sae_dump_db (int signal);`

	This is a routine that can be used to catch USR1, or 
	`<os>/meshd.c` can catch USR1 itself and call this routine
	if an `sa_handler(int)` action is not supported by the OS.

	This prints all peer instances and their current state of
	negotiation.

