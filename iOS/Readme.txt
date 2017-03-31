This folder show you how to using Feitian PKI (PK01c) card with Feitian mobile smartcard reader to do sign.


To download latest iR301 and bR301 SDK, please check:
https://github.com/FeitianSmartcardReader/bR301_SDK_Latest


Before using this application, please make sure your card has formatted and also need make sure there have certificate in your card, without certificate cannot do sign operation.


Format card:
Install PC middleware “FTSmartCard-Setup.exe”, and after insert card into your reader and do connect to PC for format, running “FTScardFormat.exe” do format.


Import certificate:
After format card, then re-plug card and using ftscManagerAdm.exe tool to do import your certificate. or through IE(internet explore) to apply from internet, the open CA website is www.cacert.org.

Feitian demo card default PIN is 1234