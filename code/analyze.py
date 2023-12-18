#!/usr/bin/env python3
import glob, importlib, sys

def main():
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

	for sn in servers:
		if len(servers[sn]) > 1:
			print(sn, servers[sn])

if __name__ == "__main__":
	main()

