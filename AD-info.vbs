'On Error Resume Next	'Don't turn this on unless absolutely necessary.  Would rather error out and fix root cause

'AD-info.vbs - Gather AD data for PBIS customers
'Version 1.6 - 2/20/14 - Ben Hendin 
'- Complete rewrite of original script to rely strictly on LDAP calls for data
'- Now can be run from any machine in forest with minimal writes
'Version 1.6.1 - 2/21/14 - Ben Hendin 
'- Updated error handling to deal with RODCs and removed rIDNextRID query
'Version 1.6.2 - 2/21/14 - Ben Hendin 
'- Updated Cell handling for user and group count
'Version 1.6.3 - 2/24/14 - Ben Hendin 
'- Included PBIS agent info
'- Fixes for querying some non-existing attributes in pre-2008 OS
'Version 1.6.4 - 2/26/14 - Ben Hendin 
'- Fixed output formatting
'- Added search for/connections to preferred uplevel DC to maximize info and stability
'- Fixed pre-schema v31 search issues
'- Added PBIS agent host OS info
'- Changed prefered runtime to wscript
'Version 1.6.5 - 2/27/14 - Ben Hendin 
'- Added error handling for DCs with no nTDSDSA (unclean DC objects)
'Version 1.6.6 - 2/27/14 - Ben Hendin 
'- Added error handling for nTDSDSA with no matching Computer Object(no metadata cleanup)
'Version 1.6.7 - 2/28/14 - Ben Hendin 
'- Various performance enhancements for LDAP queries
'Version 1.6.8 - 7/16/14 - Ben Hendin 
'- Rewrote DC lookup routines to query on existing nTDSDSA objects to eliminate non-DC site servers
'Version 1.6.9 - 7/21/14 - Ben Hendin 
'- Added additional debugging for problems looking up invalid/missing RidSetReferences
'Version 1.7 - 4/7/15 - Ben Hendin 
'- Cleaned up output with some new subroutines to give consistency and allow data to be written as retrieved
'- Added error handling for Sites with no Server objects
'- Added error handling for nTDSDSA objects with cleared attributes
'Version 1.7.1 - 4/7/15 - Ben Hendin
'- Added back change to ADO Timeout from 30 seconds to 10 minutes (was removed from an uncommited version).
'Version 1.7.2 - 12/9/15 - Ben Hendin
'- Added error handling for inability to read serverReference from parent nTDSDSA objects (gives same error as nTDSDSA issue)
'Version 1.8.0 - 11/2/17 - Rob Auch
'- add domain blacklist for domains that were not properly deleted/removed
'Version 1.9.0 - 2022-10-04 - Robert Auch and Brian King (customer)
'- Update schema versions from customer Brian King
strScriptVersion = "1.9.0"

Dim adoCommand,adoConnection
Dim intForestSchema
Dim strOffset
ReDim arrForests(-1)
ReDim arrSchemaAttrs(-1)
ReDim arrForestMap(-1)
ReDim arrDomains(-1)
ReDim arrCells(-1)
ReDim arrPBISAgents(-1)
ReDim arrLicenseContainers(-1)
ReDim arrDCs(-1)
ReDim arrTrusts(-1)
ReDim arrSites(-1)
ReDim arrSubnets(-1)

'Force script to run as cscript from command if launches as wscript
Set oShell = CreateObject("Wscript.Shell")
If Not WScript.FullName = WScript.Path & "\cscript.exe" Then
	result = MsgBox("This script performs *informational queries only* against a DC in each forest domain."  &vbCrLf &vbCrLf _
	&"Runtime should be under 60 seconds in a well connected environment." &vbCrLf &vbCrLf _
	&"Delays may indicate connection issues to DCs or remote domains" &vbCrLf &vbCrLf _
	&"This script should be run with a Domain Admin account from any system joined to the target forest." &vbCrLf &vbCrLf _
	&"All domains should be reachable from the target system in order to get complete information." &vbCrLf &vbCrLf _
	&"Output will be saved in AD-INFO.TXT" &vbCrLf,vbOKCancel+vbInformation,"BeyondTrust AD-Info Gathering Script")
	If result = 2 Then
		WScript.Quit
	End If
	flagExtraDCInfo = InputBox("The script can gather additional info for each DC." _
	&vbCrLf &vbCrLf _
	& "This requires a small amount of additional processing time, though it may cause the script to fail in unforseen environments." _
	& vbCrLf & vbcrlf _
	& "Recommendation is to leave as 'TRUE'.  Set to 'FALSE' only if the script has issues running." _
	& vbCrLf & vbcrlf _
	& "Gather additional DC info?","BeyondTrust AD-Info Gathering Script","TRUE")
	Select Case UCase(flagExtraDCInfo)
		Case ""
			WScript.Quit
		Case "TRUE" 
			flagExtraDCInfo = 1
		Case Else
			flagExtraDCInfo = 0
	End Select
	
	oShell.Run "cmd.exe /k " & WScript.Path & "\cscript.exe //NOLOGO " & Chr(34) & WScript.scriptFullName & Chr(34) &" " &strUserProvidedDC &" " &flagExtraDCInfo &" > AD-INFO.TXT",1,False
	WScript.Quit 0
End If
Set oShell = Nothing

'Setup ADO Connections
Set adoCommand = CreateObject("ADODB.Command")
Set adoConnection = CreateObject("ADODB.Connection")
adoConnection.Provider = "ADsDSOObject"
adoConnection.Open "Active Directory Provider"
Set adoCommand.ActiveConnection = adoConnection
adoCommand.Properties("Page Size") = 100
adoCommand.Properties("Timeout") = 600
adoCommand.Properties("Cache Results") = False

'Create Dictionary Objects
'Schema Versions
Set dictSchemaVersions = CreateObject("Scripting.Dictionary")
dictSchemaVersions.Add 13,"Windows 2000 Server"
dictSchemaVersions.Add 30,"Windows 2003 RTM, SP1, SP2"
dictSchemaVersions.Add 31,"Windows 2003 R2"
dictSchemaVersions.Add 44,"Windows 2008"
dictSchemaVersions.Add 47,"Windows 2008 R2"
dictSchemaVersions.Add 52,"Windows Server 2012 Beta"
dictSchemaVersions.Add 56,"Windows Server 2012"
dictSchemaVersions.Add 69,"Windows Server 2012 R2"
dictSchemaVersions.Add 87,"Windows Server 2016"
dictSchemaVersions.Add 88,"Windows Server 2019"

'Schema searchFlags
Set dictSearchFlags = CreateObject("Scripting.Dictionary")
dictSearchFlags.Add 512, "RODC_FILTERED"
dictSearchFlags.Add 256, "NEVER_AUDIT_VALUE"
dictSearchFlags.Add 128, "CONFIDENTIAL"
dictSearchFlags.Add 64, "SUBTREE_INDEX"
dictSearchFlags.Add 32, "TUPLE_INDEX"
dictSearchFlags.Add 16, "COPY"
dictSearchFlags.Add 8, "PRESERVE_ON_DELETE"
dictSearchFlags.Add 4, "ANR"
dictSearchFlags.Add 2, "CONTAINER_INDEX"
dictSearchFlags.Add 1, "INDEX"
 
'Domain and Forest Functionality
Set dictDomainAndForestFunctionality = CreateObject("Scripting.Dictionary")
dictDomainAndForestFunctionality.Add 0,"DS_BEHAVIOR_WIN2000" 
dictDomainAndForestFunctionality.Add 1,"DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS"
dictDomainAndForestFunctionality.Add 2,"DS_BEHAVIOR_WIN2003"
dictDomainAndForestFunctionality.Add 3,"DS_BEHAVIOR_WIN2008"
dictDomainAndForestFunctionality.Add 4,"DS_BEHAVIOR_WIN2008R2"
dictDomainAndForestFunctionality.Add 5,"DS_BEHAVIOR_WIN2012"
dictDomainAndForestFunctionality.Add 6,"DS_BEHAVIOR_WIN2012R2"
dictDomainAndForestFunctionality.Add 7,"DS_BEHAVIOR_WIN2016"
dictDomainAndForestFunctionality.Add 8,"DS_BEHAVIOR_WIN2019"

Set dictDomainBlackList = CreateObject("Scripting.Dictionary")

' Trust Direction
' http://msdn.microsoft.com/en-us/library/cc223768(PROT.10).aspx
Set dictTrustDirection = CreateObject("Scripting.Dictionary")
dictTrustDirection.Add 3, "BIDIRECTIONAL"
dictTrustDirection.Add 2, "OUTBOUND"
dictTrustDirection.Add 1, "INBOUND"
dictTrustDirection.Add 0, "DISABLED"

' Trust Type
' http://msdn.microsoft.com/en-us/library/cc223771(PROT.10).aspx
Set dictTrustTypes = CreateObject("Scripting.Dictionary")
dictTrustTypes.Add 4, "DCE"
dictTrustTypes.Add 3, "MIT"
dictTrustTypes.Add 2, "UPLEVEL"
dictTrustTypes.Add 1, "DOWNLEVEL"

' Trust Attributes
' http://msdn.microsoft.com/en-us/library/cc223779(PROT.10).aspx
Set dictTrustAttributes = CreateObject("Scripting.Dictionary")
dictTrustAttributes.Add 128, "UsesRC4Encryption"
dictTrustAttributes.Add 64, "TreatAsExternal"
dictTrustAttributes.Add 32, "WithinForest"
dictTrustAttributes.Add 16, "CrossOrganisation"
dictTrustAttributes.Add 8, "ForestTransitive"
dictTrustAttributes.Add 4, "QuarantinedDomain"
dictTrustAttributes.Add 2, "UpLevelOnly"
dictTrustAttributes.Add 1, "NonTransitive"

'Encryption Types
Set dictEncryptionTypes = CreateObject("Scripting.Dictionary")
dictEncryptionTypes.Add 1,"DES_CBC_CRC"
dictEncryptionTypes.Add 2,"DES_CBC_MD5"
dictEncryptionTypes.Add 4,"RC4_HMAC_MD5"
dictEncryptionTypes.Add 8,"AES128_CTS_HMAC_SHA1_96"
dictEncryptionTypes.Add 16,"AES256_CTS_HMAC_SHA1_96"

Set dictTreeMap = CreateObject("Scripting.Dictionary")
Set dictDomains = CreateObject("Scripting.Dictionary")
Set dictPBISVersions = CreateObject("Scripting.Dictionary")
Set dictPBISClientOS = CreateObject("Scripting.Dictionary")
Set dictPreferredDCs = CreateObject("Scripting.Dictionary")

'Connect to ROOTDSE to get information about Forest and Domain
Set objRootDSE = GetObject("LDAP://RootDSE")
strCurrentDomainDNS = fncConvertDNtoDNS(objRootDSE.Get("defaultNamingContext"))
strRootDomainDN = objRootDSE.Get("rootDomainNamingContext")
strRootDomainDNS = fncConvertDNtoDNS(strRootDomainDN)
strConfigurationNC = objRootDSE.Get("configurationNamingContext")
strSchemaNC = objRootDSE.Get("schemaNamingContext")
strRootDC = objRootDSE.Get("dnsHostName")

'Get command arguments
iNumberOfArguments = WScript.Arguments.Count
If iNumberOfArguments = 1 Then
	flagExtraDCInfo = WScript.Arguments.Item(0)
Else
	flagExtraDCInfo = True
End If

WScript.Echo "HEADER_RUNTIME" & vbtab & "VERSION" &vbTab & "CURRENT_DOMAIN" &vbTab &"FOREST_ROOT"
WScript.Echo "runtime" &vbTab &strScriptVersion &vbTab &strCurrentDomainDNS &vbTab &strRootDomainDNS

'WRITE FOREST MAP
Call subGetForestTrees 	'Get Forest Trees - This is just an additional sanity check to read the trees in the forest.
Call subCreateForestDomainMap("(&(NETBIOSName=*)(!trustParent=*))")
strHeader = "HEADER_MAP" &vbTab &"FQDN" &vbTab &"NETBIOS"
Call subOutputArray(strHeader,arrForestMap)

'WRITE FOREST DETAILS
Call subGetForestInfo
strHeader = "HEADER_FOREST" &vbTab &"SCHEMA_VERSION" &vbTab &"FUNCTIONAL_LEVEL" &vbTab &"SCHEMA_MASTER" &vbTab &"WHEN_CREATED"
Call subOutputArray(strHeader,arrForests)

'WRITE SCHEMA ATTRIBUTE DETAILS
Call subGetSchemaInfo
strHeader = "HEADER_SCHEMA" &vbTab & "ATTRIBUTE" &vbTab &"IS_REPLICATED_GC" &vbTab &"SEARCH_FLAGS"
Call subOutputArray(strHeader,arrSchemaAttrs)

'CHECK EACH DOMAIN FOR CONNECTIVITY AND OPTIMAL DC
For Each itemFlatDomain In dictDomains
	Call subFindOptimalDCs(itemFlatDomain)
Next

'WRITE DOMAIN/TRUST/CELL/LICENSE INFO
For Each itemFlatDomain In dictDomains
	Call subGetDomainInfo(itemFlatDomain)	'GET DOMAIN INFO
	Call subGetDomainTrusts(itemFlatDomain)	'GET TRUST INFO
	Call subGetCellList(itemFlatDomain)	'GET CELL INFO
	Call subGetLicenseInfo(itemFlatDomain)	'GET LICENSE INFO
Next

strHeader =  "HEADER_DOMAIN" &vbTab &"NETBIOS" &vbTab &"DN" &vbTab &"CONNECTED_DC" & vbtab &"FUNCTIONAL_LEVEL" &vbTab &"ALLOCATED_RIDS" &vbTab &"SID" &vbTab &"WHEN_CREATED"
Call subOutputArray(strHeader,arrDomains)
strHeader = "HEADER_TRUSTS" &vbTab &"SOURCE_NETBIOS" &vbTab &"SOURCE_FQDN" &vbTab &"DEST_NETBIOS" &vbTab &"DEST_FQDN" &vbTab &"DIRECTION" &vbTab &"TYPE" &vbTab &"ATTRIBUTES"
Call subOutputArray(strHeader,arrTrusts)
strHeader = "HEADER_CELL" &vbTab &"DOMAIN" &vbTab &"CELL_DN" &vbTab &"TYPE" &vbTab &"USE_RFC2307" &vbTab &"USER_COUNT" &vbTab &"GROUP_COUNT" _
&vbTab &"AGENT_COUNT" &vbTab &"AGENT_VERSIONS" &vbTab &"HOST_OS_TYPES"
Call subOutputArray(strHeader,arrCells)
strHeader = "HEADER_LICENSE" &vbTab &"DN" &vbTab &"AUTO_ASSIGN"
Call subOutputArray(strHeader,arrLicenseContainers)

'WRITE SITE/DC/SUBNET INFO
Call subGetSiteInfo

strHeader = "HEADER_SITE" &vbTab &"NAME"
Call subOutputArray(strHeader,arrSites)
strHeader =  "HEADER_DC" &vbTab &"NAME" &vbTab &"DOMAIN" &vbTab &"FQDN" &vbTab &"SITE" &vbTab &"ISGC" &vbTab &"ISRODC" _
&vbTab &"FUNCTIONAL_LEVEL" &vbTab &"OS" &vbTab & "RIDLOW" & vbTab & "RIDHIGH" & vbtab & "ENCTYPES"
Call subOutputArray(strHeader,arrDCs)
strHeader = "HEADER_SUBNET" &vbTab &"IPRANGE" &vbTab &"SITE"
Call subOutputArray(strHeader,arrSubnets)

'Legacy - can remove as soon as viewhealthstatus.py is updated to parse new data
'Call subLegacySite

'---------------------------------------------------------------------------------------------------
'Begin Subroutines and Functions
'---------------------------------------------------------------------------------------------------

Sub subGetForestTrees	'Get all Trees in the local computer's Forest
	Set objSysInfo = CreateObject("ADSystemInfo")
	arrGetTrees = objSysInfo.GetTrees
	Set dictTreeMap = CreateObject("Scripting.Dictionary")
	For Each strTree In arrGetTrees
		dictTreeMap.Add fncConvertDNStoDN(strTree),strTree
	Next
End Sub

Sub subCreateForestDomainMap(strFilter)
	strBase = "<LDAP://" & strRootDC &"/" & strConfigurationNC & ">"
	strAttributes = "cn,msDS-Behavior-Version,ncname,nETBIOSNAME,distinguishedName,trustParent"
	strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";subtree"
	adoCommand.CommandText = strQuery	
	
	Set adoRecordSet = adoCommand.Execute

	On Error Resume Next
	errCheck = adoRecordSet.BOF
	Select Case Err.Number
		Case 0
		Case -2147217865
			WScript.Echo "ERR" &vbTab & "Please check connection and credentials to domain"	&vbTab &Err.Number	&vbTab	& Err.Description
			WScript.Quit
		Case -2147016661
			WScript.Echo "ERR" &vbTab & "Please run from a domain joined system"	&vbTab &Err.Number	&vbTab	& Err.Description
			WScript.Quit
		Case Else
			WScript.Echo "ERR" &vbTab & "An unknown error occured" &vbTab &Err.Number	&vbTab	& Err.Description
			WScript.Quit
	End Select
	On Error Goto 0
	
	
	While Not adoRecordSet.EOF
		strncname = adoRecordSet.Fields("ncname").Value
		strnETBIOSNAME = adoRecordSet.Fields("cn")	'Checking CN instead of nETBIOSNAME, since the latter can technically be edited
		strdistinguishedName = adoRecordSet.Fields("distinguishedName")
		strtrustParent = adoRecordSet.Fields("trustParent")
			
		If dictTreeMap.Exists(strncname) Then
			strConfirmed = "*"
		Else
			strConfirmed = "!"
		End If

		If IsNull(strtrustParent) Then
			strOffset = ""
		Else
			strOffset = strOffset & "."
			strConfirmed = ""
		End if
		
		'STORE MAP
		ReDim Preserve arrForestMap(UBound(arrForestMap)+1)
		arrForestMap(UBound(arrForestMap)) = "map" &vbTab & strOffset & fncConvertDNtoDNS(strncname) &vbTab & strnETBIOSNAME &vbTab &strConfirmed
		
		'UPDATE DICTIONARY FOR EASY ENUMERATION
		dictDomains.Add strNetBIOSNAME,strncname
		
		Call subCreateForestDomainMap("(&(NETBIOSName=*)(trustParent=" &strdistinguishedName & "))")
		
		strOffset = ""
		
		adoRecordSet.MoveNext
	Wend
End Sub

Sub subGetForestInfo
	Set objSchema = GetObject("LDAP://" & strRootDC &"/" & strSchemaNC)
	intForestSchema = objSchema.objectVersion
	intWhenCreated = objSchema.whenCreated
	strfSMORoleOwner = objSchema.fSMORoleOwner
	
	If dictSchemaVersions.Exists(intForestSchema) Then
		strForestSchema = dictSchemaVersions(intForestSchema)
	End If	
	
	Set objSchema = GetObject("LDAP://" &strRootDC &"/CN=Partitions," & strConfigurationNC)
	
	On Error Resume next
	intmsDSBehaviorVersionForest = objSchema.Get("msDS-Behavior-Version")	'Get Forest Functional Level
	If Err.Number <> 0 Then
		strmsDSBehaviorVersion = "(?)RUN AS ADMIN"
	Else 
		If dictDomainAndForestFunctionality.Exists(intmsDSBehaviorVersionForest) Then
			strmsDSBehaviorVersionForest = "(" & intmsDSBehaviorVersionForest &")" & dictDomainAndForestFunctionality(intmsDSBehaviorVersionForest)
		End If	
	End If
	On Error Goto 0
	
	ReDim Preserve arrForests(UBound(arrForests)+1)
	arrForests(UBound(arrForests)) = "forest" &vbTab &"(" &intForestSchema &")"& strForestSchema 	&vbTab & strmsDSBehaviorVersionForest &vbTab & strfSMORoleOwner &vbTab & intWhenCreated
End Sub

Sub subGetSchemaInfo	
	strBase = "<LDAP://" & strRootDC &"/" & strSchemaNC & ">"
	strFilter = "(|(name=UnixHomeDirectory)(name=uidNumber)(name=uid)(name=LoginShell)(name=GidNumber)(name=Gecos)(name=Display-Name))"
	strAttributes = "name,distinguishedName,isMemberOfPartialAttributeSet,searchFlags"	
	strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";subtree"
	
	adoCommand.CommandText = strQuery	
	Set adoRecordSet = adoCommand.Execute
			
	While Not adoRecordSet.EOF
		strSearchFlags = ""
		strName = adoRecordSet.Fields("name")
		strisMemberOfPartialAttributeSet = adoRecordSet.Fields("isMemberOfPartialAttributeSet")
		If IsNull(strisMemberOfPartialAttributeSet) Then
			strisMemberOfPartialAttributeSet = False
		End If
		intsearchFlags = adoRecordSet.Fields("searchFlags")
		If IsNull(intsearchFlags) Then
			intsearchFlags = 0
		End If
		For Each dblSearchFlag in dictSearchFlags
			If intsearchFlags And dblSearchFlag Then
				strSearchFlags = strSearchFlags & dictSearchFlags(dblSearchFlag) & ","
		    End If
	    Next
	    If Right(strSearchFlags,1)="," Then
	    	strSearchFlags = Mid(strSearchFlags,1,Len(strSearchFlags)-1)
	    End If
	    ReDim Preserve arrSchemaAttrs(UBound(arrSchemaAttrs)+1)
		arrSchemaAttrs(UBound(arrSchemaAttrs)) = "schema" &vbTab & strName &vbTab &strisMemberOfPartialAttributeSet &vbTab &"(" &intsearchFlags &")" &strSearchFlags 
		adoRecordSet.MoveNext
	Wend
	
End Sub

Sub subFindOptimalDCs(flatDomain)
	strDomainDN = dictDomains(flatDomain)
	strDomainDNS = fncConvertDNtoDNS(strDomainDN)	
    if dictDomainBlackList.exists(flatDomain) Then
        ' Domain is bad, need to skip it and move on
        Exit Sub
    End If

	strBase = "<LDAP://" &strDomainDNS &"/" &strConfigurationNC &">"
	strFilter = "(objectClass=nTDSDSA)"
	strAttributes = "ADsPath"
	strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";subtree"

	adoCommand.CommandText = strQuery
    On Error Resume Next
	Set adoRecordSet = adoCommand.Execute
    if Not Err.Number = 0 Then
        dictDomainBlackList.Add flatDomain,strDomainDN
        dictDomains.Remove flatDomain
        Exit Sub
    End If
    On Error Goto 0
		
	intmsDSBehaviorVersionDCHighest = -1
	
	While Not adoRecordSet.EOF
		strnTDSADN = adoRecordset.Fields("AdsPath").Value
		Set objDC = GetObject(GetObject(adoRecordset.Fields("AdsPath").Value).Parent)
		strSiteServerDN = objDC.distinguishedName
		strDCDNSNAme = objDC.dnsHostName
		strDCDN = objDC.serverReference
		strDCDomainDN = fncExtractDomainFromDN(strDCDN)

		If strDomainDN = strDCDomainDN then
			Set objNTDSSettings = GetObject(strnTDSADN)
			intmsDSBehaviorVersionDC = objNTDSSettings.get("msDS-Behavior-Version")
			
			If intmsDSBehaviorVersionDC > intmsDSBehaviorVersionDCHighest Then	'If this is the highest functional level we have encountered
				On Error Resume Next
				Set objUpLevelDC = GetObject("LDAP://" &strDCDNSNAme)
				If Err.Number = 0 Then	'And If we can connect to it!
					If dictPreferredDCs.Exists(strDCDomainDN) Then
						dictPreferredDCs.Remove(strDCDomainDN)	'Remove the current preferred server
					End If
					dictPreferredDCs.Add strDCDomainDN,strDCDNSNAme	'And replace it with this one
					intmsDSBehaviorVersionDCHighest = intmsDSBehaviorVersionDC	'Increment the highest level
				End If
				On Error Goto 0
			End If
		End If
		adoRecordSet.MoveNext
	Wend
	
	If Not dictPreferredDCs.Exists(strDomainDN) Then	'Remove all domains where a suitable DC could not be found
    	ReDim Preserve arrDomains(UBound(arrDomains)+1)
		arrDomains(UBound(arrDomains)) = "domain" &vbTab & flatDomain &vbTab & "CONNECT_ERROR" &vbTab & "SKIP" &vbTab & "SKIP"
		dictDomains.Remove flatDomain
	End If
End Sub

Sub subGetDomainInfo(flatDomain)	
	strDomainDN = dictDomains(flatDomain)
	strDomainDNS = fncConvertDNtoDNS(strDomainDN)
	strPreferredServer = dictPreferredDCs(strDomainDN)
    if dictDomainBlackList.exists(flatDomain) Then
        ' Domain is bad, need to skip it and move on
        Exit Sub 
    End If
	
	'Get Domain Functional Level
	Set objDC = GetObject("LDAP://" &strPreferredServer)
	intmsDSBehaviorVersionDomain = objDC.Get("msDS-Behavior-Version")
	If dictDomainAndForestFunctionality.Exists(intmsDSBehaviorVersionDomain) Then
		strmsDSBehaviorVersionDomain = "(" & intmsDSBehaviorVersionDomain &")" & dictDomainAndForestFunctionality(intmsDSBehaviorVersionDomain)
	End If
	
	'Get Additonal Info
	intobjectSid = objDC.Get("objectSid")
	pureSidData = OctetToHexStr(intobjectSid)
	sDDLSidStr = HexStrToSID(pureSidData)
	intWhenCreated = objDC.Get("whenCreated")
	
	'GetRIDInfo
	Set objrIDAvailablePool = GetObject("LDAP://" &strPreferredServer &"/CN=RID Manager$,CN=System," & strDomainDN)
	Set intrIDAvailablePool = objrIDAvailablePool.Get("rIDAvailablePool")

  	'get the large integer into two long values (high part and low part)
    intrIDAvailablePoolHigh = intrIDAvailablePool.HighPart
    intrIDAvailablePoolLow = intrIDAvailablePool.LowPart
    If (intrIDAvailablePoolLow < 0) Then
       intrIDAvailablePoolHigh = intrIDAvailablePoolHigh + 1 
    End If
        
    'STORE DOMAINS
    ReDim Preserve arrDomains(UBound(arrDomains)+1)
	arrDomains(UBound(arrDomains)) = "domain" &vbTab & flatDomain &vbTab & dictDomains(flatDomain)&vbTab &strPreferredServer &vbTab & strmsDSBehaviorVersionDomain &vbTab _
	&intrIDAvailablePoolLow &vbTab & sDDLSidStr & vbTab & intWhenCreated
End Sub

Sub subGetDomainTrusts(flatDomain)
	strDomainDN = dictDomains(flatDomain)
	strDomainDNS = fncConvertDNtoDNS(strDomainDN)
	strPreferredServer = dictPreferredDCs(strDomainDN)
    if dictDomainBlackList.exists(flatDomain) Then
        ' Domain is bad, need to skip it and move on
        Exit Sub
    End If

	strBase = "<LDAP://" & strPreferredServer & ">"
	strFilter = "(objectCategory=trustedDomain)"
	strAttributes = "flatName,distinguishedName,trustDirection,trustType,trustAttributes"
	strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";subtree"
	
	adoCommand.CommandText = strQuery	
	Set adoRecordSet = adoCommand.Execute

	While Not adoRecordSet.EOF
		strflatNameTo = adoRecordSet.Fields("flatName")
		arrdistinguishedName = Split(adoRecordSet.Fields("distinguishedName"),",")
		strDNSTo = Mid(arrdistinguishedName(0),4)
		inttrustDirection = adoRecordSet.Fields("trustDirection")
		inttrustType = adoRecordSet.Fields("trustType")
		inttrustAttributes = adoRecordSet.Fields("trustAttributes")
		
		If dictTrustDirection.Exists(inttrustDirection) Then
			strtrustDirection = dictTrustDirection(inttrustDirection)
		End If
		If dictTrustTypes.Exists(inttrustType) Then
			strtrustType = dictTrustTypes(inttrustType)
		End If
		
		strTAFlags = ""
	    For Each dblTAFlag in dictTrustAttributes
			If inttrustAttributes And dblTAFlag Then
				strTAFlags = strTAFlags & dictTrustAttributes(dblTAFlag) & ","
		    End If
	    Next		
	    If Right(strTAFlags,1)="," Then
	    	strTAFlags = Mid(strTAFlags,1,Len(strTAFlags)-1)
	    End If
		adoRecordSet.MoveNext
		
		'STORE TRUSTS
		ReDim Preserve arrTrusts(UBound(arrTrusts)+1)
		arrTrusts(UBound(arrTrusts)) = "trust" &vbTab & flatDomain &vbTab &strDomainDNS &vbTab &strflatNameTo &vbTab & strDNSTo &vbTab _
		&"(" &inttrustDirection &")" & strtrustDirection  &vbTab &"(" &inttrustType &")" & strtrustType &vbTab &"(" &inttrustAttributes &")"& strTAFlags
	Wend
End Sub

Sub subGetSiteInfo
	strSitesContainer = "LDAP://" &strRootDC &"/CN=Sites," & strConfigurationNC
	Set objSitesContainer = GetObject(strSitesContainer)
	objSitesContainer.Filter = Array("site")
	
	For Each objSite In objSitesContainer
		strSiteName = objSite.cn
		
		'STORE SITES
		ReDim Preserve arrSites(UBound(arrSites)+1)
	    strSiteInfo = "site" &vbTab & strSiteName

	    'Get All Servers in Sites
	    strSiteRDN = objSite.Name
	    'strServersPath = "LDAP://" &strRootDC &"/CN=Servers," & strSiteRDN & ",CN=Sites," & strConfigurationNC
		
		strBase = "<LDAP://" &strRootDC &"/CN=Servers," & strSiteRDN & ",CN=Sites," & strConfigurationNC &">"
		strFilter = "(objectClass=nTDSDSA)"
		strAttributes = "ADsPath"
		strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";subtree"

		adoCommand.CommandText = strQuery	
	
		On Error Resume Next
		
		Set adoRecordSet = adoCommand.Execute
			
		Select Case Err.Number
			Case 0
				strSiteInfo = strSiteInfo
			Case -2147217865
				strSiteInfo = strSiteInfo &vbTab & "ERROR" &vbTab & Replace(Err.Description,vbCrLf,"") &" (" & Err.Number &")" &vbTab & "(No Servers container found in site)"
		End Select
		
		On Error Goto 0
		
		arrSites(UBound(arrSites)) = strSiteInfo
					
		While Not adoRecordSet.EOF
			strnTDSDSADN = adoRecordset.Fields("AdsPath").Value
			Set objDC = GetObject(GetObject(adoRecordset.Fields("AdsPath").Value).Parent)
	    	strDCName = objDC.cn
	    	strdNSHostName = objDC.dNSHostName
	    	strserverReference = objDC.serverReference
			
	    	If strserverReference = "" Then
	    		strPreferredServer = "DC_DELETED"
	    	Else
		    	strDomainNameDN = fncExtractDomainFromDN(strserverReference)
		    	strDomainNameDNS = fncConvertDNtoDNS(strDomainNameDN)
		    	strPreferredServer = dictPreferredDCs(strDomainNameDN)
			End If
			
			On Error Resume Next	'These values may be cleared (?)
			
	    	Set objNTDSSettings = GetObject(strnTDSDSADN)
			intOptions = objNTDSSettings.get("options")
			intmsDSBehaviorVersionDC = objNTDSSettings.get("msDS-Behavior-Version")
			
			On Error Goto 0
				
	    	If intOptions And 1 Then
				isGC = True
			Else
				isGC = False
			End If
			
			'Read from each DC object for extra info.
			If flagExtraDCInfo Then
				Select Case strPreferredServer
					Case ""	'No DC was reachable
						strExtraInfo = "ERR_SKIP" & vbTab & "NO_DC_FOUND"
					Case "DC_DELETED"	'DC Computer object was removed (but nTDSDSA remains)
						strExtraInfo = "ERR_SKIP" & vbTab & "nTDSDSA_NO_MATCHING_DC_OBJECT"
					Case Else
						strExtraInfo = fncGetDCDetails(strPreferredServer,strserverReference,intmsDSBehaviorVersionDC)
				End Select
			Else
				strExtraInfo = "flagExtraDCInfo=0"
			End If
			
			'STORE DCS
			ReDim Preserve arrDCs(UBound(arrDCs)+1)
			arrDCs(ubound(arrDCs)) = "dc" & vbTab & strDCName &vbTab &strDomainNameDNS &vbTab &strdNSHostName _
			&vbTab & strSiteName &vbTab & isGC & vbTab & strExtraInfo
			adoRecordSet.MoveNext
	    Wend

	    'Get Subnets in the site
	    subnetCount = 0
			
		' Set batch to retrieve 1000 members at a time.
		lastBatch = False
		intBatchSize = 999
		intStartBatch = 0
		intEndBatch = intStartBatch + intBatchSize
		
		Do While True
		    If (lastBatch = False) Then
		    	adoCommand.CommandText = "SELECT 'siteObjectBL;range=" _
		    	& intStartBatch & "-" & intEndBatch &"',distinguishedName FROM '" _
		    	&"LDAP://" &strRootDC &"/CN=Sites," &strConfigurationNC _
		    	&"' WHERE objectCategory='site' AND distinguishedName='"& objSite.distinguishedName &"'"    
		    Else
		    	adoCommand.CommandText = "SELECT 'siteObjectBL;range=" _
		    	& intStartBatch & "-*',distinguishedName FROM '" _
		    	&"LDAP://" &strRootDC &"/CN=Sites," &strConfigurationNC _
		    	&"' WHERE objectCategory='site' AND distinguishedName='"& objSite.distinguishedName &"'"  
		    End If
		
			adoCommand.Properties.Item("Searchscope") = 2	'Set searchscope back to subtree 
		    Set objSubnetRecordSet = adoCommand.Execute

		    intCount = 0
	
		    Do Until objSubnetRecordSet.EOF
		        For Each subnetField In objSubnetRecordSet.Fields
		        	If IsArray(subnetField)Then
		                For Each subnet In subnetField.Value
		                	arrSubnet=Split(subnet,",")
		                	'STORE SUBNETS
		                	ReDim Preserve arrSubnets(UBound(arrSubnets)+1)
		                	arrSubnets(UBound(arrSubnets)) = "subnet" &vbTab & Mid(arrSubnet(0),4) & vbTab & strSiteName
		                	intCount = intCount + 1
		                	subnetCount = subnetCount + 1
		                Next
			        End If
		        Next
		        objSubnetRecordSet.MoveNext
			Loop
			objSubnetRecordSet.Close
		
		    ' Exit Loop for last bt
		    If (lastBatch = True) Then
				Exit Do
		    End If
		
		    'Retrieve last batch of < 1000 members
		    If (intCount = 0) Then
		        lastBatch = True
		    Else
		        ' Setup to retrieve next 1000 members.
		        intStartBatch = intEndBatch + 1
		        intEndBatch = intStartBatch + intBatchSize
		    End If
		Loop		
	Next
End Sub

Sub subGetCellList(flatDomain)
	strDomainDN = dictDomains(flatDomain)
	strDomainDNS = fncConvertDNtoDNS(strDomainDN)
	strPreferredServer = dictPreferredDCs(strDomainDN)
    if dictDomainBlackList.exists(flatDomain) Then
        ' Domain is bad, need to skip it and move on
        Exit Sub
    End If
	
	strBase = "<LDAP://" &strPreferredServer & ">"
	strFilter = "(cn=$LikewiseIdentityCell)"
	strAttributes = "distinguishedName"	
	strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";subtree"
	
	adoCommand.CommandText = strQuery	
	Set adoRecordSet = adoCommand.Execute
	
	isDefaultCell = 0
	While Not adoRecordSet.EOF
		strCellDN = adoRecordSet.Fields("distinguishedName")
		If strCellDN = "CN=$LikewiseIdentityCell," & strDomainDN Then
			isDefaultCell = 1
		End if
		Call subGetCellInfo(strDomainDN,strCellDN)
		adoRecordSet.MoveNext
	Wend
	
	If isDefaultCell = 0 then
		'Get objects with UID/GID set - even if no cells (for comparison)
		intUserCount = fncGetObjectCount(strDomainDN,strDomainDN,True,"DEFAULT","Users")
		intGroupCount = fncGetObjectCount(strDomainDN,strDomainDN,True,"DEFAULT","Groups")
		
		'Get count/list of all PBIS agents
		arrAgentInfo = fncGetPBISComputerCount(strPreferredServer,strDomainDN)	'Get Computer count overall
		intAgentCount = arrAgentInfo(0)
		strAgentVersions = arrAgentInfo(1)
		strAgentOS = arrAgentInfo(2)
	
		If intUserCount > 0 Or intGroupCount > 0 or intAgentCount > 0 Then	'Print info if any objects are found
			ReDim Preserve arrCells(UBound(arrCells)+1)
			arrCells(UBound(arrCells)) = "cell" & vbTab & fncConvertDNtoDNS(strDomainDN) &vbTab & "N/A" &vbTab & "N/A" & vbTab & "TRUE" _
			& vbTab & intUserCount & vbTab & intGroupCount &vbTab & intAgentCount &vbTab & strAgentVersions &vbTab & strAgentOS
		End If
	End if
End Sub

Sub subGetCellInfo(strDomainDN,strDistinguishedName)
	strDomainDNS = fncConvertDNtoDNS(strDomainDN)
	strPreferredServer = dictPreferredDCs(strDomainDN)
	
	'Determine Cell Type
	If InStr(strdistinguishedName,"OU=") = 0 Then
		strCellType = "DEFAULT"
	Else
		strCellType = "NAMED"
	End If
	
	strCellName = "CN=$LikewiseIdentityCell," & strCellOU
	
	Set objCell = GetObject("LDAP://" & strPreferredServer &"/" & strdistinguishedName)
	
	arrDescription = objCell.GetEx("description") 
	
	'Determine if Cell is in DI Mode
	struse2307Attrs = FALSE
	For i = 0 To UBound(arrDescription)   
	    If InStr(arrDescription(i),"use2307Attrs=True") > 0 Then
	    	struse2307Attrs = TRUE
	    End If
	Next
	
	'Get counts of Users and Groups in Cell
	intUserCount = fncGetObjectCount(strDomainDN,strdistinguishedName,struse2307Attrs,strCellType,"Users")
	intGroupCount = fncGetObjectCount(strDomainDN,strdistinguishedName,struse2307Attrs,strCellType,"Groups")
	
	'Get PBIS Agent Info
	arrAgentInfo = fncGetPBISComputerCount(strPreferredServer,strDistinguishedName)
	intAgentCount = arrAgentInfo(0)
	strAgentVersions = arrAgentInfo(1)
	strAgentOS = arrAgentInfo(2)
	
	'STORE CELL INFO
	ReDim Preserve arrCells(UBound(arrCells)+1)
	arrCells(UBound(arrCells)) = "cell" & vbTab & fncConvertDNtoDNS(strDomainDN) &vbTab & strdistinguishedName &vbTab _
	& strCellType & vbTab & struse2307Attrs & vbTab & intUserCount & vbTab & intGroupCount & vbtab & intAgentCount &vbtab & strAgentVersions &vbTab & strAgentOS
End Sub

Sub subGetLicenseInfo(flatDomain)	
	strDomainDN = dictDomains(flatDomain)
	strDomainDNS = fncConvertDNtoDNS(strDomainDN)
	strPreferredServer = dictPreferredDCs(strDomainDN)
    if dictDomainBlackList.exists(flatDomain) Then
        ' Domain is bad, need to skip it and move on
        Exit Sub
    End If
	
	Set objConnection = CreateObject("ADODB.Connection")
	objConnection.Provider = "ADsDSOObject"
	objConnection.Open "Active Directory Provider"
	strFilter = "(cn=$LikewiseEnterpriseLicenses)"

	Set objRecordSet = objConnection.Execute("<LDAP://" &strPreferredServer & ">;" & strFilter & ";" & "distinguishedName;subtree")

	While Not objRecordSet.EOF
		strdistinguishedName = objRecordSet.Fields("distinguishedName")
		
		Set objCell = GetObject("LDAP://" & strPreferredServer &"/" & strdistinguishedName)
		
		arrDescription = objCell.GetEx("description") 
		
		strAutoAssign = FALSE
		For i = 0 To UBound(arrDescription)   
		    If InStr(arrDescription(i),"AutoAssign=True") > 0 Then
		    	strAutoAssign = TRUE
		    End If
		Next
		
		'STORE LICENSE INFO		
		ReDim Preserve arrLicenseContainers(UBound(arrLicenseContainers)+1)
		arrLicenseContainers(UBound(arrLicenseContainers)) = "license" & vbTab & strdistinguishedName &vbTab &strAutoAssign
		
		objrecordset.MoveNext
	Wend
End Sub

Sub subLegacySite
	WScript.Echo vbCrLf & "---------------LEGACY INFO--------------"
	strSitesContainer = "LDAP://" &strRootDC &"/CN=Sites," & strConfigurationNC
	Set objSitesContainer = GetObject(strSitesContainer)
	objSitesContainer.Filter = Array("site")
	 
	For Each objSite In objSitesContainer
	    WScript.Echo String(40,"-")
	    Wscript.Echo "SITE: " & mid(objSite.Name,4)
	    Wscript.Echo vbCr
	    strSiteRDN = objSite.Name
	    strServersPath = "LDAP://" &strRootDC &"/CN=Servers," & strSiteRDN & ",cn=Sites," & strConfigurationNC
	
	    'Get Servers in Site
	    Set objServersContainer = GetObject(strServersPath)
	    wscript.echo "SERVERS:"
	    For Each objServer In objServersContainer
	        WScript.Echo Mid(objServer.Name,4)
	    Next
	    Wscript.echo vbCrLf
	
	    'Get Subnets in the site
	    WScript.Echo "SUBNETS:" 
	    subnetCount = 0
		Set objCommand = CreateObject("ADODB.Command")
		Set objConnection = CreateObject("ADODB.Connection")
		objConnection.Provider = "ADsDSOObject"
		objConnection.Open = "Active Directory Provider"
		objCommand.ActiveConnection = objConnection
		objCommand.Properties("Page Size") = 100
		objCommand.Properties("Timeout") = 30
		objCommand.Properties("Cache Results") = False
			
		' Set batch to retrieve 1000 members at a time.
		lastBatch = False
		intBatchSize = 999
		intStartBatch = 0
		intEndBatch = intStartBatch + intBatchSize

		Do While True
		    If (lastBatch = False) Then
		    	objCommand.CommandText = "SELECT 'siteObjectBL;range=" _
		    	& intStartBatch & "-" & intEndBatch &"',distinguishedName FROM '" _
		    	&"LDAP://" &strRootDC &"/CN=Sites," &strConfigurationNC _
		    	&"' WHERE objectCategory='site' AND distinguishedName='"& objSite.distinguishedName &"'"    
		    Else
		    	objCommand.CommandText = "SELECT 'siteObjectBL;range=" _
		    	& intStartBatch & "-*',distinguishedName FROM '" _
		    	&"LDAP://" &strRootDC &"/CN=Sites," &strConfigurationNC _
		    	&"' WHERE objectCategory='site' AND distinguishedName='"& objSite.distinguishedName &"'"  
		    End If

		    Set objSubnetRecordSet = objCommand.Execute

		    intCount = 0
	
		    Do Until objSubnetRecordSet.EOF
		        For Each subnetField In objSubnetRecordSet.Fields
		        	If IsArray(subnetField)Then
		                For Each subnet In subnetField.Value
		                	arrSubnet=Split(subnet,",")
		                	WScript.Echo Mid(arrSubnet(0),4)
		                	intCount = intCount + 1
		                	subnetCount = subnetCount + 1
		                Next
			        End If
		        Next
		        objSubnetRecordSet.MoveNext
			Loop
			objSubnetRecordSet.Close
		
		    ' Exit Loop for last bt
		    If (lastBatch = True) Then
				Exit Do
		    End If
		
		    'Retrieve last batch of < 1000 members
		    If (intCount = 0) Then
		        lastBatch = True
		    Else
		        ' Setup to retrieve next 1000 members.
		        intStartBatch = intEndBatch + 1
		        intEndBatch = intStartBatch + intBatchSize
		    End If
		Loop
		
	    WScript.Echo String(40,"-")
	    wscript.echo vbCrLF
	Next
End Sub

Sub subOutputArray(strHeader,arrItems)
	If UBound(arrItems) >= 0 Then
		WScript.Echo strHeader
		For Each item In arrItems
			WScript.Echo item
		Next
	End If
End Sub

Function fncGetPBISComputerCount(strPreferredServer,strCellDN)
	If Left(strCellDN,25) = "CN=$LikewiseIdentityCell," Then
		strOUDN = Mid(strCellDN,26)
		strDisplayDN = strCellDN
	Else 
		strOUDN = strCellDN
		strDisplayDN = "N/A"
	End If

	'Get PBIS Computers joined to domain
	strBase = "<LDAP://" &strPreferredServer &"/" & strOUDN & ">"
	strFilter = "(&(objectCategory=Computer)(|(operatingSystemServicePack=PBIS*)(operatingSystemServicePack=Likewise*)))"
	strAttributes = "distinguishedName,operatingSystemServicePack,operatingSystem,operatingSystemVersion"	
	strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";subtree"

	adoCommand.CommandText = strQuery	
	Set adoRecordSetComputers = adoCommand.Execute
	
	dictPBISVersions.RemoveAll
	dictPBISClientOS.RemoveAll
	
	While Not adoRecordSetComputers.EOF
		intCount = intCount + 1
		strOSServicePack = adoRecordSetComputers.Fields("operatingSystemServicePack")
		strOS = adoRecordSetComputers.Fields("operatingSystem") &" " & adoRecordSetComputers.Fields("operatingSystemVersion")
		If Not dictPBISVersions.Exists(strOSServicePack) Then
			dictPBISVersions.Add strOSServicePack,strDomainDN
		End If
		If Not dictPBISClientOS.Exists(strOS) Then
			dictPBISClientOS.Add strOS,strDomainDN
		End If	
		adoRecordSetComputers.MoveNext
	Wend

	For Each version In dictPBISVersions
		strVersions = strVersions &"," & version
	Next
	strVersions = Mid(strVersions,2,Len(strVersions))
	
	For Each clientOS In dictPBISClientOS
		If clientOS = " " Then
			strClientOS = strClientOS &"," & "[NULL]"
		Else
			strClientOS = strClientOS &"," & clientOS
		End If
	Next
	strClientOS = Mid(strClientOS,2,Len(strClientOS))

	Dim arrAgentsFunction(2)
	arrAgentsFunction(0) = intCount 
	arrAgentsFunction(1) = strVersions
	arrAgentsFunction(2) = strClientOS
	fncGetPBISComputerCount = arrAgentsFunction	
End function	

Function fncConvertDNStoDN(strDomainDNS)
	Dim arrDomainParts,intX
	
	arrDomainParts = Split(strDomainDNS,".")
	For intX = 0 To UBound(arrDomainParts)
		arrDomainParts(intX) = "DC=" & arrDomainParts(intX)
	Next	
	fncConvertDNStoDN = Join(arrDomainParts,",")
End Function

Function fncConvertDNtoDNS(strDomainDN)
	Dim arrDomainParts
	
	arrDomainParts = Split(strDomainDN,",")
	fncConvertDNtoDNS = Join(arrDomainParts,".")
	fncConvertDNtoDNS = Replace(fncConvertDNtoDNS,"DC=","")
End Function

Function fncExtractDomainFromDN(strObjectDN)
	If strObjectDN <> "" Then
		fncExtractDomainFromDN = Mid(strObjectDN,InStr(strObjectDN,"DC="))
	End if
End Function

Function fncGetDCDetails(strPreferredServer,strserverReference,intmsDSBehaviorVersionDC)	
	strBase = "<LDAP://" & strPreferredServer &"/" & strserverReference &">"
	strFilter = "(objectClass=*)"
	
	If intForestSchema > 31 Then
		strAttributes = "operatingSystem,operatingSystemServicePack,operatingSystemVersion,rIDSetReferences,primaryGroupID,msDS-SupportedEncryptionTypes"
	Else
		strAttributes = "operatingSystem,operatingSystemServicePack,operatingSystemVersion,rIDSetReferences,primaryGroupID"
		intEncTypes = 7
	End If
	
	strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";base"

	adoCommand.CommandText = strQuery

	On Error Resume Next	'Need in case we can't connect to DC
	Set adoRecordSetDC = adoCommand.Execute
	If Err.Number <> 0 Then
		fncGetDCDetails = "CONNECT_ERR" & vbTab & strBase & vbTab & Err.Number &vbtab & Trim(Err.Description)
		Exit Function
	Else		
		While Not adoRecordSetDC.EOF
			strOS = adoRecordSetDC.Fields("operatingSystem")
			strSP = adoRecordSetDC.Fields("operatingSystemServicePack")
			strVer = adoRecordSetDC.Fields("operatingSystemVersion")
			arrrIDSetReferences = adoRecordSetDC.Fields("rIDSetReferences")
			intEncTypes = adoRecordSetDC.Fields("msDS-SupportedEncryptionTypes")
			Select Case adoRecordSetDC.Fields("primaryGroupID")	'Determine if RODC
				Case 521
					isRODC = True
				Case 516
					isRODC = False
			End Select
			adoRecordSetDC.MoveNext
		Wend
	End If
	On Error Goto 0
	
	'Calculate DC Functional Level
	If dictDomainAndForestFunctionality.Exists(intmsDSBehaviorVersionDC) Then
		strmsDSBehaviorVersionDC = "(" & intmsDSBehaviorVersionDC &")" & dictDomainAndForestFunctionality(intmsDSBehaviorVersionDC)
	End If
	
	'Get EncTypes
	strEncTypes=""
	For Each dblETFlag in dictEncryptionTypes
		If intEncTypes And dblETFlag Then
			strEncTypes = strEncTypes & dictEncryptionTypes(dblETFlag) & ","
	    End If
	Next		
    If Right(strEncTypes,1)="," Then
    	strEncTypes = Mid(strEncTypes,1,Len(strEncTypes)-1)
    End If
	
	'Get RID Info
	Select Case isRODC
		Case True
			intrIDAllocationPoolHigh = "N/A"
			intrIDAllocationPoolLow = "N/A"
		Case False	'Only ask RWDC
			If IsArray(arrrIDSetReferences) Then
				For Each intIDSetReference In arrrIDSetReferences
					If InStr(intIDSetReference,"0ADEL") > 0 Then
						'WScript.Echo intIDSetReference & " DELETED!"	'Not displaying since we are not dcdiag!
					Else
						strrIDSetReferences = intIDSetReference
					End If
				Next
				
				On Error Resume Next
				Set objDCRID = GetObject("LDAP://" & strPreferredServer &"/" & strrIDSetReferences)
		    	Set intrIDAllocationPool = objDCRID.get("rIDAllocationPool")
			    intrIDAllocationPoolHigh = intrIDAllocationPool.HighPart
			    intrIDAllocationPoolLow = intrIDAllocationPool.LowPart
			    If (intrIDAllocationPoolLow < 0) Then
			       intrIDAllocationPoolHigh = intrIDAllocationPoolHigh + 1 
			    End If
			    If Err.Number <> 0 Then
				    intrIDAllocationPoolHigh = "ERROR"
					intrIDAllocationPoolLow = "ERROR"
					WScript.Echo "LDAP://" & strPreferredServer &"/" & strrIDSetReferences
					WScript.Echo "ERR" &vbTab & "Could not retrieve RidSetReferences"	&vbTab &Err.Number	&vbTab	& Err.Description & vbTab & "LDAP://" & strPreferredServer &"/" & strrIDSetReferences
				End If
				On Error Goto 0	
						    
			Else
				intrIDAllocationPoolHigh = "NULL"
				intrIDAllocationPoolLow = "NULL"
			End If
		Case Else
			isRODC = "NULL"
			intrIDAllocationPoolHigh = "NULL"
			intrIDAllocationPoolLow = "NULL"
	End Select
	
	fncGetDCDetails = isRODC &vbtab &strmsDSBehaviorVersionDC &vbtab &"(" &strVer &")" & strOS &" " & strSP &vbTab & intrIDAllocationPoolLow & vbTab & intrIDAllocationPoolHigh &vbTab &"(" & intEncTypes &")" &strEncTypes
End Function

Function fncGetObjectCount(strDomainDN,strdistinguishedName,struse2307Attrs,strCellType,strObjectType)	
	strDomainDNS = fncConvertDNtoDNS(strDomainDN)
	'Get Object Count
	Select Case True
		Case strCellType = "DEFAULT" And struse2307Attrs
			strBase = "<LDAP://" & strDomainDNS & ">"
			Select Case strObjectType
			Case "Users"
				strFilter = "(&(objectCategory=Person)(uidNumber=*)(gidNumber=*))"
			Case "Groups"
				strFilter = "(&(objectCategory=Group)(gidNumber=*))"
			End Select
			strAttributes =  "cn"
		Case Else
			strBase = "<LDAP://" & strDomainDNS &"/CN=" &strObjectType &"," & strdistinguishedName & ">"
			strFilter = "(objectCategory=serviceConnectionPoint)"
			strAttributes =  "cn"
	End Select

	strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";subtree"
	adoCommand.CommandText = strQuery

	Set adoRecordSet = adoCommand.Execute

	fncGetObjectCount = adoRecordSet.RecordCount
End Function

Function HexStrToSID(strSid) 
'converts a raw SID hex string to the according SID string (SDDL)
    Dim i, data, offset
    ReDim data(Len(strSid)/2 - 1) 
    For i = 0 To UBound(data) 
        data(i) = CInt("&H" & Mid(strSid, 2*i + 1, 2)) 
    Next 
    HexStrToSID = "S-" & data(0) & "-" & Byte6ToLong(data(2), data(3), data(4), data(5), data(6), data(7))

    blockCount = data(1)
    For i = 0 To blockCount - 1
        offset = 8 + 4*i
        HexStrToSID = HexStrToSID & "-" & Byte4ToLong(data(offset+3), data(offset+2), data(offset+1), data(offset))
    Next
End Function 


'_________________________________________________________________________________________ helper functions 

Function OctetToHexStr(var_octet)
'converts pure binary data to a string with the according hexadecimal values
    OctetToHexStr = ""
    For n = 1 To lenb(var_octet)
        OctetToHexStr = OctetToHexStr & Right("0" & hex(ascb(midb(var_octet, n, 1))), 2)
    Next
End Function


Function Byte4ToLong(ByVal b1, ByVal b2, ByVal b3, ByVal b4)
'converts 4 bytes to the according lang integer value
    Byte4ToLong = b1
    Byte4ToLong = Byte4ToLong * 256 + b2
    Byte4ToLong = Byte4ToLong * 256 + b3
    Byte4ToLong = Byte4ToLong * 256 + b4
End Function


Function Byte6ToLong(ByVal b1, ByVal b2, ByVal b3, ByVal b4, ByVal b5, ByVal b6)
'converts 6 bytes to the according lang integer value
    Byte6ToLong = b1
    Byte6ToLong = Byte6ToLong * 256 + b2
    Byte6ToLong = Byte6ToLong * 256 + b3
    Byte6ToLong = Byte6ToLong * 256 + b4
    Byte6ToLong = Byte6ToLong * 256 + b5
    Byte6ToLong = Byte6ToLong * 256 + b6
End Function
