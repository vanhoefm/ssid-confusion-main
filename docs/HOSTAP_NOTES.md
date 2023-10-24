When scanning, `nl80211_parse_bss_info` takes the beacon from `NL80211_BSS_BEACON_IES`
and saves it into the end of `struct wpa_bss` in the field `ies`.

The function `wpa_supplicant_get_beacon_ie` also seems to get it from cached scan results.
That ends of using the field `wpa_bss_ie_ptr` which uses `bss->ies`.

Note that we can track where `wpa_supplicant_install_bigtk` is called to see at which
points we possibly have to verify the beacon integrity.

