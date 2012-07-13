FloodBlocker
------------
FloodBlocker — MetaMod Plugin that fixes some server vulnerabilities.

At this moment it has next fixes:

* Fixes fake connects flood.
* Fixes engine vulnerability, that allow to download some critical files, like server.cfg and any other.

About
-----
Project uses CMake for cross compilation. Compilation tested on next configurations:

* Unix Makefiles
* Visual Studio 9 2008
* Visual Studio 10

Other configuration is unsupported.
CMakeList.txt located in directory *build*.

Credits
-------
Created specially for [Dedicated-Server.RU](http://dedicated-server.ru)