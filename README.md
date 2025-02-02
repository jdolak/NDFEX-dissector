This is a Wireshark dissector for the NDFEX protocol for Notre Dames's HFT Techonologies SP 2025 class.
  
This was made by:
    - Jachob Dolak

![protocol example screenshot](./ndfex_screenshot.jpg)

## Installation

To install, copy this file to your Wireshark plugins direcroty.  
  This can be done with the following command on MacOS:  

    `cp ./wireshark_dissector.lua /Applications/Wireshark.app/Contents/PlugIns/wireshark/wireshark_dissector.lua`
  and reloading Wireshark's plugins.

## Contributing

This was done very quick and dirty so please make an issue or PR if something can be improved.

More on wireshark dissectors can be found here:
- [https://wiki.wireshark.org/lua/dissectors](https://wiki.wireshark.org/lua/dissectors)




