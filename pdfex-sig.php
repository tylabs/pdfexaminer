<?PHP

/*
 * v3.0 May 17 2018
 * pdfex-sig.php: tyLabs.com PDFExaminer - signatures
 * This file should not be edited as it will be replaced repeatedly.
 * To add your own signatures, edit pdfex.php and include your own script after pdfex-lib.php is included.
 * Adding to the signatures works like this:
 * $PDFstringSearch['new signature'] = "name here";
 * $PDFhexSearch['new hexidecimal signature'] = "name here";
 * $PDFblockHash['new md5 object or file hash'] = "name here";
 */


$global_pdfex_engine = $global_engine= 79; //detection engine update

include_once('pdfex-lib.php');


	$PDFstringSearch = array('une(.{0,6}?)sca(.{0,6}?)pe([^\)]{0,6}?)\(' => 'suspicious.obfuscation using unescape',
//openaction (#4f|O)(#70|p)(#65|e)(#6e|n)(#41|A)(#63|c)(#74|t)(#69|i)(#6f|o)(#6e|n)
'un(.{0,6}?)esc(.{0,6}?)ape([^\)]{0,6}?)\(' => 'suspicious.obfuscation using unescape', 
'unesc([\W]{0,6}?)ape' => 'suspicious.obfuscation using unescape', 
'c([\W]{0,4}?)h([\W]{0,4}?)a([\W]{0,4}?)r([\W]{0,4}?)C([\W]{0,3}?)o([\W]{0,3}?)d([\W]{0,3}?)e([\W]{0,3}?)A(.{0,3}?)t' => 'suspicious.obfuscation using charCodeAt', 
'u([\W]{0,6}?)n([\W]{0,6}?)e([\W]{0,6}?)s([\W]{0,6}?)c([\W]{0,6}?)a([\W]{0,6}?)p([\W]{0,6}?)e' => 'suspicious.obfuscation using unescape',
'unescape([^\)]{0,6}?)\(' => 'suspicious.obfuscation using unescape',
'nopblock' => 'suspicious.string nopblock', 
//'u9090' => 'suspicious.string unicode nop', 
//'u0c0c' => 'suspicious.string heap spray shellcode', 
//'0c0c0c0c' => 'suspicious.string heap spray shellcode', 
'eval(\s{0,3}?)\(' => 'suspicious.obfuscation using eval',
//'eval\(' => 'suspicious.obfuscation using eval',
'eval\\' => 'suspicious.obfuscation using eval',
//'eval (' => 'suspicious.obfuscation using eval',
'JavaScript/JS' => 'suspicious.javascript object',
'application/x-javascript' => 'suspicious.javascript in XFA block',
'application#2Fx-javascript' => 'suspicious.javascript in XFA block',
'application#2Fpdf' => 'suspicious.pdf embedded PDF file',
//'application/pdf' => 'suspicious.pdf embedded PDF file',
'eval,' => 'suspicious.obfuscation using eval',
'toString\(' => 'suspicious.obfuscation toString',
'substr\(' => 'suspicious.obfuscation using substr',
"'e'(.{1,30}?)'va'(.{1,3}?)'l" => 'suspicious.obfuscation using eval',
"'re'(.{1,24}?)'place'"  => 'suspicious.obfuscation using String.replace',
'"l","v","e","a"' => 'suspicious.obfuscation using eval',
'"u","s","p","c","n","e","a",'  => 'suspicious.obfuscation using unescape',
'"rCo","t","cha","","deA"' => 'suspicious.obfuscation using String.fromCharCode',
'"e","l","a","v"' => 'suspicious.obfuscation using eval',
'"s","n","a","e","c","u","e","p"'  => 'suspicious.obfuscation using unescape',
'"deA","cha","rCo","t"' => 'suspicious.obfuscation using String.fromCharCode',
'=(\s{0,6}?)eval' => 'suspicious.obfuscation using eval',
'from([\W]{0,6}?)C([\W]{0,6}?)h([\W]{0,6}?)a(.{0,6}?)r(.{0,6}?)C(.{0,6}?)o([\W]{0,6}?)d([\W]{0,6}?)e' => 'suspicious.obfuscation using String.fromCharCode',
'.fromCharC' => 'suspicious.obfuscation using String.fromCharCode',
'.replace' => 'suspicious.obfuscation using String.replace',
'\.substring(\s{0,3}?)\(' => 'suspicious.obfuscation using substring',
'byteToChar' => 'suspicious.obfuscation using util.byteToChar',
 '%u9090' => 'suspicious.string Shellcode NOP sled',
'"%" + "u" + "0" + "c" + "0" + "c" + "%u" + "0" + "c" + "0" + "c"' => 'suspicious.string heap spray shellcode', 
'%u4141%u4141' => 'suspicious.string shellcode',
'Run_Sploit'=>'suspicious.string Run_Sploit',
'HeapSpray'=>'suspicious.string HeapSpray',
'writeMultiByte' => 'suspicious.flash writeMultiByte',
'addFrameScript' => 'suspicious.flash addFrameScript',
//fuzzString('JBIG2Decode') => 'pdf.exploit vulnerable JBIG2Decode CVE-2009-0658',
'\/'.fuzzString('RichMedia') => 'suspicious.flash Adobe Shockwave Flash in a PDF define obj type',
'/R#69chM#65#64ia#53e#74ti#6e#67#73/' => 'suspicious.flash obfuscated name',
//'Subtype/3D' => 'pdf.exploit suspicious use of 3D CVE-2009-3954',
//'model/u3d' => 'pdf.exploit suspicious use of U3D CVE-2009-3953 CVE-2009-3959',
'Predictor 02(\s{0,2}?)\/(\s{0,2}?)Colors 1073741838' => 'pdf.exploit FlateDecode Stream Predictor 02 Integer Overflow CVE-2009-3459',
'\/Colors \d{5,15}?' => 'pdf.exploit colors number is high CVE-2009-3459',
'URI.{1,30}?\/\.\.\/\.\.' => 'pdf.exploit URI directory traversal',
'URI.{1,65}?system32' => 'pdf.exploit URI directory traversal system32',
'\/Action(.{0,64}?)\.exe' => 'pdf.exploit execute EXE file',
'\/Action(.{0,64}?)system32' => 'pdf.exploit access system32 directory',
//'exportDataObject' => 'pdf.exploit accessing embedded files exportDataObject',
'Launch/Type/Action/Win' => 'pdf.exploit execute action command',
'printSeps' => 'pdf.exploit printSeps memory heap corruption CVE-2010-4091',

':++$,$$$$:' => 'suspicious.obfuscation jjencoded javascript',
'$$:++$,$$$' => 'suspicious.obfuscation jjencoded javascript',

'g(\W{0,2}?)e(\W{0,2}?)t(\W{0,2}?)A([\W]{0,2}?)n([\W]{0,1}?)n([\W]{0,2}?)o([\W]{0,2}?)t' => 'suspicious.obfuscation getAnnots access blocks',
'info([\W]{0,4}?)\.([\W]{0,4}?)Trailer' => 'suspicious.obfuscation info.Trailer to access blocks',
'app.setTimeOut' => 'suspicious.obfuscation using app.setTimeOut to eval code',
'Run_Sploit' => 'suspicious.string -Run_Sploit-',
'HeapSpray' => 'suspicious.string -HeapSpray-', 
'var shellcode' => 'suspicious.string -shellcode-',
'Collabb([\W]{0,6}?).([\W]{0,6}?)collectEmailInfo' => 'pdf.exploit Collab.collectEmailInfo CVE-2008-0655',
'CollabcollectEmailInfo' => 'pdf.exploit Collab.collectEmailInfo CVE-2008-0655',
'Collab([\W]{0,6}?).([\W]{0,6}?)getIcon' => 'pdf.exploit Collab.getIcon CVE-2009-0927',
'Collab.get(.{1,24}?)Icon' => 'pdf.exploit Collab.getIcon CVE-2009-0927',
'Collab.getIcon' => 'pdf.exploit Collab.getIcon CVE-2009-0927',
'util.printd' => 'pdf.suspicious util.printd used to fill buffers',
//'med(.*?)ia(.*?)newPlay(.*?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'med(.{1,24}?)ia(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'med(.{1,24}?)ia(.{1,24}?)newPlay(.{1,24}?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'me(.{1,24}?)dia\.(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'me(.{1,24}?)dia\.(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'Collab.collectEmailInfo' => 'pdf.exploit Collab.collectEmailInfo CVE-2008-0655',
'mediaa([\W]{0,6}?)newPlayer' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'media(.{1,24}?)newPlayer' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'media.newPlayer' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'spell(.{1,24}?)customDictionaryOpen' => 'pdf.exploit spell.customDictionaryOpen CVE-2009-1493',
'spell.customDictionaryOpen' => 'pdf.exploit spell.customDictionaryOpen CVE-2009-1493',
'util(.{1,24}?)printf(.{1,24}?)45000f' => 'pdf.exploit util.printf CVE-2008-2992',
'contentType=(.{0,6}?)image\/(.{0,30}?)CQkJCQkJCQkJCQkJCQkJCQkJ' => 'pdf.exploit using TIFF overflow CVE-2010-0188',
'exploit.tif' => 'suspicious.string TIFF overflow exploit.tif name CVE-2010-0188',
'kJCQ,kJCQ,kJCQ,kJCQ,kJCQ,kJCQ' => 'pdf.exploit using TIFF overflow CVE-2010-0188',
'JCQkJCQkJCQkJCQkJCQkJCQkJCQk' => 'suspicious.string base 64 nop sled used in TIFF overflow CVE-2010-0188',
'TU0AKgAAIDgMkAyQDJAMkAyQDJAMk' => 'suspicious.string base 64 nop sled used in TIFF overflow CVE-2010-0188',
'J.{1,2}?C.{1,2}?Q.{1,2}?k.{1,2}?J.{1,2}?C.{1,2}?Q.{1,2}?k.{1,2}?J.{1,2}?C.{1,2}?Q.{1,2}?k' => 'suspicious.string base 64 nop sled used in TIFF overflow CVE-2010-0188',
'+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4' => 'suspicious.string base 64 nop sled used in TIFF overflow CVE-2010-0188',
'ImageField1(.{0,6}?)xfa:contentType=(.{0,6}?)image\/tif' => 'pdf.exploit TIFF overflow CVE-2010-0188',
'Launch/Type/Action/Win' => 'pdf.exploit exec action command',
'\/Action(.{0,24}?)\.exe' => 'pdf.execute exe file',
'\/Action(.{0,36}?)system32' => 'pdf.execute access system32 directory',
//'exportDataObject' => 'pdf.exploit accessing embedded files exportDataObject',
'Launch/Type/Action/Win' => 'pdf.exploit execute action command',
'M9090M9090M9090M9090' => 'suspicious.string obfuscated unicode NOP sled',
hex2bin('BB1500070003FE7FB27F0007BB15000711000100ACA80007BB15000700010100ACA80007F772000711000100E2520007545C0007FFFFFFFF000101000000000004010100001000004000000031D70007BB1500075A526A024D15000722A70007BB15000758CD2E3C4D15000722A70007BB150007055A74F44D15000722A70007BB150007B849492A4D15000722A70007BB150007008BFAAF4D15000722A70007BB15000775EA87FE4D15000722A70007BB150007EB0A5FB94D15000722A70007BB150007') => 'pdf.exploit TIFF overflow CVE-2010-0188',
//hex2bin('070000010300010000003020000001010300010000000100000003010300010000000100000006010300010000000100000011010400010000000800000017010400010000003020000050010300CC0000009220000000000000000C0C0824010100F772000704010100BB150007001000004D150007BB1500070003FE7FB27F0007BB15000711000100ACA80007BB15000700010100ACA80007F772000711000100E2520007545C0007FFFFFFFF000101000000000004010100001000004000000031D70007BB1500075A526A024D15000722A70007BB15000758CD2E3C4D15000722A70007BB150007055A74F44D15000722A70007BB150007B849492A4D15000722A70007BB150007008BFAAF4D15000722A70007BB15000775EA87FE4D15000722A70007BB150007EB0A5FB94D15000722A70007BB150007E00300004D15000722A70007BB150007F3A5EB094D15000722A70007BB150007E8F1FFFF4D15000722A70007BB150007FF9090904D15000722A70007BB150007FFFFFF904D15000731D700072F110007') => 'pdf.exploit TIFF overflow CVE-2010-0188',
'^FWS(.{1}?)' => 'suspicious.flash Embedded Flash',
'^CWS(.{1}?)' => 'suspicious.flash Embedded Flash',
'^SWF(.{1}?)' => 'suspicious.flash Embedded Flash',
hex2bin("0D0A43575309A2D20000789CECBD797C54") => 'suspicious.flash Embedded Flash',

'application#2Fx-shockwave-flash' => 'suspicious.flash Embedded Flash define obj',
'application/x-shockwave-flash' => 'suspicious.flash Embedded Flash define obj',
'SING(.{0,366}?)'.hex2bin('41414141414141414141') => 'pdf.exploit fontfile SING table overflow CVE-2010-2883 generic',

hex2bin('1045086F0000EB4C00000024686D747809C68EB20000B4C4000004306B65726EDC52D5990000BDA000002D8A6C6F6361F3CBD23D0000BB840000021A6D6178700547063A0000EB2C0000002053494E47D9BCC8B50000011C00001DDF706F7374B45A2FBB0000B8F40000028E70726570') => 'pdf.exploit fontfile SING table overflow CVE-2010-2883 A',

hex2bin('4657530947CB0000480140005A0000190100441108000000BF141CCB0000000000000010002E00060080804094A8D0A001808004100002000000121212E24130F00931343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134') => 'flash.exploit CVE-2011-0609',

hex2bin('7772697465427974650541727261799817343635373533304143433035303030303738') => 'flash.exploit CVE-2011-0611', 
hex2bin('5131645443737746414142346E453155625778545A52512B743733742B3362744B4E30596E617767552F414452654D5848334777597276757737597A643743674A734A6C76643174374E716D393959576D4B676B5A7674686C68446942556E344D694645453030514659306D456F664A2B4F45504D55594E6F69614C526D4E696A4D45494444665065652B3139663534652B35356E764F63383578376532766732514551504148514C6B45384248683175303937414B7741654943394F6A336579756277574E52793141564A475939326D4777444832794278794147636569424250524348') => 'flash.exploit CVE-2011-0611',
hex2bin('343635373533304143433035303030303738303030353546303030303046413030303030313830313030343431313030303030303030334630334137303530303030393630433030303530303037393543333743313330374642433337433133304531323944303230303443303439443032303031383030383831353030303930303431') => 'flash.exploit CVE-2011-0611',

hex2bin('076A69745F65676708') => 'flash.suspicious jit_spray', 
hex2bin('3063306330633063306330633063306306537472696E6706') => 'flash.exploit CVE-2011-0611', 
hex2bin('410042004300440045004600470048004900A18E110064656661756C74') => 'flash.exploit CVE-2011-0611', 
hex2bin('00414243444500566B6475686752656D686677317375727772777C73680064656661756C740067657453697A650047647768317375727772777C73680077777273757277') => 'flash.exploit CVE-2011-0611', 
//hex2bin('586D6C537766094D6F766965436C6970076A69745F656767086368696C64526566') => 'flash.exploit CVE-2011-0611', 
hex2bin('34363537353330394541433730303030373830303036343030303030304338303030303032443031303034343131313830303030303034333032463446344634383630363036303230303031303030304646303931303030303030303033303030313030383630363036303130303032303030303430303030303030424631313235') => 'flash.exploit CVE-2011-0609', 
hex2bin('3941303139413031394130313941303139064C6F61646572') => 'flash.exploit CVE-2011-0609', 
//hex2bin('537472696E6704434D594B094D6F766965436C6970076A69745F656767086368696C64526566') => 'flash.exploit CVE-2011-0611', 
'AAB4AAVfAAAPoAAAGAEARBEAAAAAPwOnBQAAlgwABQAHlcN8Ewf7w3wTDhKdAgBMBJ0CABgAiBUACQBBAEIAQwBEAEUARgBHAEgASQChjhEAZGVmYXVsdAABAAQqAAIAmAGWCgAHWMBJSAenP7a3YJ0CAAAAmQIASQBAlgUABxZ0cAtMYp0CAAwAhwEAAxeHAQABlgoAB' => 'flash.exploit CVE-2011-0611',

hex2bin('066F3A40AE366A4360DFCBEF8C38CA0492794B79E942BD2BB95B866065A4750119DACF6AF72A773CDEF1117533D394744A14734B18A166C20FDE3DED19D4322E') => 'pdf.exploit U3D CVE-2011-2462 A',

hex2bin('ED7C7938945DF8FF9985868677108DA58C922C612A516FA9D182374A8B868AA25284242D8A3296B497B74849D2A210D14EA94654A2452ACA2B29D18268A5B7C5EF7E') => 'pdf.exploit PRC CVE-2011-4369 A',
hex2bin("537472696E6706586D6C537766094D6F766965436C6970076A69745F656767086368696C645265660D446973706C61794F626A656374074D79566964656F05566964656F044D794E430D4E6574436F6E6E656374696F6E") => 'flash.exploit flash calling malformed MP4 CVE-2012-0754',
'(\&\#0*97;|a)(\&\#0*112;|p)(\&\#0*112;|p)(\&\#0*108;|l)(\&\#0*105;|i)(\&\#0*99;|c)(\&\#0*97;|a)(\&\#0*116;|t)(\&\#0*105;|i)(\&\#0*111;|o)(\&\#0*110;|n)(\&\#0*47;|\/)(\&\#0*120;|x)(\&\#0*45;|\-)(\&\#0*106;|j)(\&\#0*97;|a)(\&\#0*76;|v)(\&\#0*97;|a)(\&\#0*115;|s)(\&\#0*99;|c)(\&\#0*114;|r)(\&\#0*105;|i)(\&\#0*112;|p)(\&\#0*116;|t)(.{0,1}?)' => 'suspicious.javascript in XFA block',

hex2bin('6D703405566964656F0A6E6574436F6E6E6563740D4E6574436F6E6E656374696F6E096E657453747265616D094E657453747265616D') => 'flash.exploit MP4 Loader CVE-2012-0754 B',
hex2bin('6D70343269736F6D000000246D646174018080800E1180808009029F0F808080020001C0101281302A056DC00000000D63707274')  => 'flash.exploit MP4 CVE-2012-0754',

"push(.{1,5}?)xfa.datasets.createNode(.{1,5}?)dataValue"  => 'pdf.exploit Sandbox Bypass CVE-2013-0641',

"image.jpeg(.{1,5}?)Qk0AAAAAAAAAAAAAAABAAAAALAEAAAEAAAABAAgAAQAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAUkdC"  => 'pdf.exploit BMP RLE integer heap overflow CVE-2013-2729',
"function(.{1,24}?)app.addToolButton"  => 'pdf.exploit ToolButton use-after-free CVE-2014-0496',
"function(.{1,24}?)app.removeToolButton"  => 'pdf.exploit ToolButton use-after-free CVE-2014-0496',
"app.addToolButton"=> 'suspicious.javascript addToolButton',
"<image>Qk0AAAAAAAAAAAAAAABAAAAALAEAAAEAAAABAAgAAQAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAUkdC"  => 'pdf.exploit BMP RLE integer heap overflow CVE-2013-2729',
"\/Type\/Filespec\/F(.{1,30}?)\.doc" => 'suspicious.embedded doc file',
"\/Type\/Filespec\/F(.{1,30}?)\.xls" => 'suspicious.embedded xls file',
"\/Type\/Filespec\/F(.{1,30}?)\.ppt" => 'suspicious.embedded ppt file',
"\/Type\/Filespec\/F(.{1,30}?)\.pps" => 'suspicious.embedded ppt file',
"\/Type\/Filespec\/F(.{1,30}?)\.scr" => 'suspicious.embedded scr file',
"\/Type\/Filespec\/F(.{1,30}?)\.exe" => 'suspicious.embedded exe file',
"\/Type\/Filespec\/F(.{1,30}?)\.bat" => 'suspicious.embedded bat file',
"\/Type\/Filespec\/F(.{1,30}?)\.rtf" => 'suspicious.embedded rtf file',
"\/Type\/Filespec\/F(.{1,30}?)\.mso" => 'suspicious.embedded mso file',
"\/Type\/Filespec\/F(.{1,30}?)\.htm" => 'suspicious.embedded html file',
"^\xd0\xcf\x11\xe0(.{1}?)"  => 'suspicious.embedded OLE document header',
"S /URI /URI"  => 'suspicious.embedded external content',
hex2bin("0C6A5020200D0A870A0000041D6A703268000000166968647200000020000000200001FF070000000003FC636D617000")  => 'pdf.exploit Corrupted JPEG2000 CVE-2018-4990',

);



	$PDFhexSearch = array(
'fb97fd0f' => 'shellcode.hash  CloseHandle',
'a517007c' => 'shellcode.hash  CreateFileA',
'72feb316' => 'shellcode.hash  CreateProcessA',
'25b0ffc2' => 'shellcode.hash  DeleteFileA',
'7ed8e273' => 'shellcode.hash  ExitProcess',
'efcee060' => 'shellcode.hash  ExitThread',
'aafc0d7c' => 'shellcode.hash  GetProcAddress',
'c179e5b8' => 'shellcode.hash  GetSystemDirectoryA',
'd98a23e9' => 'shellcode.hash  _hwrite',
'5b4c1add' => 'shellcode.hash  _lclose',
'ea498ae8' => 'shellcode.hash  _lcreat',
'8e4e0eec' => 'shellcode.hash  LoadLibraryA',
'db8a23e9' => 'shellcode.hash  _lwrite',
'f08a045f' => 'shellcode.hash  SetUnhandledExceptionFilter',
'add905ce' => 'shellcode.hash  WaitForSingleObject',
'98fe8a0e' => 'shellcode.hash  WinExec',
'1f790ae8' => 'shellcode.hash  WriteFile',
'e5498649' => 'shellcode.hash  accept',
'a41a70c7' => 'shellcode.hash  bind',
'e779c679' => 'shellcode.hash  closesocket',
'ecf9aa60' => 'shellcode.hash  connect',
'a4ad2ee9' => 'shellcode.hash  listen',
'b61918e7' => 'shellcode.hash  recv',
'a41970e9' => 'shellcode.hash  send',
'6e0b2f49' => 'shellcode.hash  socket',
'd909f5ad' => 'shellcode.hash  WSASocketA',
'cbedfc3b' => 'shellcode.hash  WSAStartup',
'361a2f70' => 'shellcode.hash  URLDownloadToFileA',
'9090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090' => 'suspicious.shellcode NOP Sled');

$PDFblockHash = array(
'ea24ea1063f49c594f160a57c268d034' => 'flash.exploit CVE-2010-1297',
'8286cc6dc7e2193740f6413b6fc55c7e' => 'flash.exploit CVE-2010-1297',
'ac69d954d9e334d089927a1bc875d13d' => 'flash.exploit CVE-2010-1297',
'0ab61f2fe334e22b4defb18587ae019f' => 'flash.exploit CVE-2010-1297',
'49ddb9b210e773b987b9a25678f65577' => 'flash.exploit CVE-2010-1297',
'bd7eac5ae665ab27346e52278f367635' => 'flash.exploit CVE-2010-1297',
'4666a447105b483533b2bbd0ab316480' => 'flash.exploit CVE-2010-1297',
'8a4bb4b4b837aa1623fbb82938ba5100' => 'flash.exploit CVE-2010-1818',
'86293036e961af07c747f013d946301d' => 'flash.exploit CVE-2010-1297',
'86293036e961af07c747f013d946301d' => 'flash.exploit CVE-2009-1862',
'5e645fc4e7f7e3a21ba5127a8d2c2740' => 'flash.exploit CVE-2010-3654',
'8ff29ae0d2f2e8f44d82eda6b421f6eb' => 'flash.exploit CVE-2010-3654',
'069c8fe3bda864ad79e3f367f9fce3f7' => 'flash.exploit CVE-2010-3654',
'bda6a3ed554ce561f5e9b5e68b91959f' => 'flash.exploit CVE-2010-3654',
'346a67733ab9d0f7667a34565573780d' => 'flash.exploit CVE-2010-3654',
'ec79b58f58ad1225f1d97b15e4e775b8' => 'flash.exploit CVE-2010-3654',
'11ab584578571ba3c146353815823272' => 'flash.exploit CVE-2010-3639',
'8a4bb4b4b837aa1623fbb82938ba5100' => 'flash.exploit CVE-2010-2884',
'529ae8c6ac75e555402aa05f7960eb0d' => 'flash.exploit CVE-2010-2884', //vt
'0edf3454971c9deeb12d171a02b5d0a7' => 'flash.exploit JIT-spray', 
'5cdc4bb86c5d3b4338ad56a58f54491a' => 'flash.exploit JIT-spray', //vt
'40792ec6d7b7f66e71a3fdf2e58cb432' => 'flash.exploit CVE-2011-0609',//pdf 3d1fc4deb5705c750df6930550c2fc16
'00cf8b68cce68a6254b6206f250540fd' => 'flash.exploit CVE-2011-0609',
'b9da2f3987b2e958077f51c7feea54fa' => 'flash.exploit CVE-2011-2100 heapspray',//pdf 7ea84b62da84dcd8b6f577d670c86f68
'7cf3637aada1f0ed931f8796d92fd989' => 'flash.exploit CVE-2011-0611',
'97ff733a21bb0199caf07a84358d6349' => 'flash.exploit CVE-2011-0611',//pdf 9ead2b29d633bdac3b2cd4a16b2629a2
'ad92cb017d25a897f5b35e08b1707903' => 'flash.exploit CVE-2011-0611',
'ac8c381d95a9e4dc5d4532f691fe811d' => 'flash.exploit CVE-2011-0611',
'befbf2fed66de5cd04b6f998cdbdbab0' => 'flash.exploit CVE-2011-0611',
'7e9e040ee9bd1ab5aeb953a01fd1c689' => 'flash.exploit CVE-2011-0611',
'606d898f2267c2e29fd93b613532916c' => 'flash.exploit CVE-2011-0611',
'c56dd87772312ba032fc6ac8928d480f' => 'flash.exploit CVE-2011-0611',
'b17b606bbbaebc6373dd07c0f9cda809' => 'flash.exploit CVE-2011-0611',
'62974e97067c47fcd5ca26419d93cb88' => 'flash.exploit CVE-2011-0611',
'c93c03a7ad3da4e849379ad0a9569b60' => 'flash.exploit CVE-2011-0611',
'9da516f2d64987a2e1d0859e81544a6c' => 'flash.exploit CVE-2011-0611',
'2288f8fb599433b04188bf70a7d7df34' => 'flash.exploit CVE-2011-0611',
'e103fcc0ebfdda299dfda3c4dda34c7b' => 'pdf.exploit U3D CVE-2011-2462',
'e7a878f01517d6c5d742ac2243af9297' => 'pdf.exploit PRC CVE-2011-4369',

'1ab800674234fd3047e9fc7af6d2b8e3' => 'flash.exploit CVE-2011-0611',
'7f7536ece98a987aae362450b27a9061' => 'flash.exploit CVE-2011-0611',

'28a477a94807151fb757fa8601f7a77f' => 'flash.exploit CVE-2010-1297 msf',
'2d0a674b8920afb6ff90d1bd42d83415' => 'flash.exploit CVE-2010-3654 msf',
'b67eaf93669119733055fd7cd4c52496' => 'flash.exploit CVE-2011-0609 msf',
'86b6d302eb790c3780ef3fa79d72eefc' => 'flash.exploit CVE-2011-0611 msf',
'f709ccfb785d6280c37a3641fbb6f3f5' => 'flash.exploit CVE-2012-0754 msf',
'3a901db9dbcc2c6abfc916be7880400e' => 'flash.exploit MP4 Loader CVE-2012-0754 B',
'a04f6ef8693ad53d6c3115b7728a346b' => 'flash.exploit MP4 CVE-2012-0754',
);

function fuzzString($string) {
	$out = '';
	for($i=0; $i < strlen($string); $i++) {
		$out .= "(".$string[$i]."|#".dechex(ord($string[$i])).")";

	}
	return $out;
}


?>
