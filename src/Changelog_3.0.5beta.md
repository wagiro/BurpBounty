# Improvements Burp Bounty 3.0.5beta:

### Choose insertion points type for one profile
For better optimization, now you can choose the insertion point type for one profile. For example, for discover new application paths, you only will choose the "Path discover" insertion point type, avoiding other innecesaries requests. 


![insertionpointtype](https://github.com/wagiro/BurpBounty/blob/master/images/insertionpointtype.png)


### Fixed error with redirections

In some cases the regex for redirection can cause 100% of the CPU usage.
