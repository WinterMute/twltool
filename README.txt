TWLTool v1.6, by WulfyStylez.
5/25/2016

Special thanks to Martin Korth, CaitSith2, Team Twiizers, Yellows8, Neimod, 3DSGuy, Dazzozo, and Shiny Quagsire.

NOTES ON CONSOLEIDs:
For ease of use, DSi and 3DS consoleID entry varies a bit. 
DSi consoleIDs are made to be pasted from the ascii TWCert in exported DSi titles. Internally, these are endian-swapped and processed in reverse word order. This doesn't really matter to end-users, but it's good to know.
3DS consoleIDs are a straight dump of the consoleID registers (i.e. little-endian, first then second word). This ID can be copied from ITCM (address 0x01FFB808, i.e. offset 0x3808) or cracked relatively quickly due to a security bug with IDs only having 31 bits of entropy (so 2^31-1 tries, or about 20GB's worth of AES crypto)
tl;dr: if you're doing something with 3DS files and there's a --3ds flag, be sure to use it!