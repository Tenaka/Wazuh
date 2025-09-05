# Wazuh


msiexec /i "wazuh-agent-4.12.0-1.msi" /q WAZUH_MANAGER='192.168.90.100' 

.\Sysmon64.exe -accepteula -i sysmonconfig.xml  

Windows Wazuh client
ossec.conf - C:\Program Files (x86)\ossec-agent\ossec.conf - update for addtional sysmon rules

Wazuh server - update local rules with this
local_rules.xml

Copy sysmon, wazuh agent and config files to admin desktop\wazuh - execute in order

CD "$env:HOMEPATH\Desktop\wazuh"
msiexec /i "wazuh-agent-4.12.0-1.msi" /q WAZUH_MANAGER='192.168.90.100' 
.\Sysmon64.exe -accepteula -i sysmonconfig.xml  
Copy-Item .\ossec.conf "C:\Program Files (x86)\ossec-agent" -Force
restart-service WazuhSvc
