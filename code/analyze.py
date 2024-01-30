#!/usr/bin/env python3
import glob, importlib, sys

def main():
	# Dictionary that maps the RADIUS's CommonName to a list
	# of corresponding SSIDs.
	servers = dict()

	sys.path.append("data")
	for installer in glob.glob("data/profile*"):
		installer = installer[5:-3]
		module = importlib.import_module(installer)
		sn = module.Config.server_match
		ssids = module.Config.ssids

		if not sn in servers:
			servers[sn] = ssids
		else:
			servers[sn] += ssids

	# This outputs networks with a different SSID but the
	# same CommonName for the RADIUS server. So those SSIDs
	# likely use the same credentials for authentication.
	for sn in servers:
		if len(servers[sn]) > 1:
			print(sn, servers[sn])

if __name__ == "__main__":
	main()

