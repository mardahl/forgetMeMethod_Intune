# The forgetMeMethod for running Intune PowerShell scripts repeatedly
## A.K.A the Obi-Wan Method

This script PoC will always be run by Intune Management Extension, not just once, but forever.
This means, that every time Intune Management Extension runs, it will think it needs to run this script again.
The interval is officially every hour, but I have seen it run every 30 minutes once in a while.

The benefit of this method is also that the last success or failure is logged in the Intune portal.

## Requirements:
- Designed to be run in system context (so not as the user).
- Should be run in 64Bit mode, as the script will delete a registry entry in the 64bit registry.


## forgetMeMethod.ps1
- PoC that this can be done, modify to suit your needs (you might want to cleanup some of the temp files it makes to prove it works)

## forgetMeMethod_with_user_exec.ps1
- PoC that we can also make this execute certain things as the user currently logged on to the system, even though we have to run this in SYSTEM context to trick IME into running this script again and again and...


