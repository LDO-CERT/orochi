rule Example_Two
{
strings:
$MaliciousWeb1 = "www.scamwebsite.com"
$MaliciousWeb2 = "www.notrealwebsite.com"
$Maliciousweb3 = "www.freemoney.com"
$AttackerName1 = "hackx1203"
$AttackerName2 = "Hackor"
$AttackerName3 = "Hax"

condition:
any of them
}
