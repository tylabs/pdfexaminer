<?PHP

/*
 * v3.0 Jun 1 2016
 * pdfex-cli.php: tyLabs.com PDFExaminer - command line library
 * This file contains the processing code for command line specific use
 * where data is not stored in a DB for web server rendering.
 */
//optional variable to save files in the directory below in a md5 subdir
$global_store_files = 0;

//directory to store extracted PDF objects
$pdfdir = './';

//export all object data to command line
$global_export_all = 0;

include_once ('pdfex-sig.php');

//object placeholders
$pdfobjTable = array('obj_id' => '', 'gen_id' => '', 'dup_id' => '', 'key' => '', 'md5_raw' => '', 'md5_decoded' => '',
		'filters' => '', 'params' => '', 'filename_raw' => '', 'filename_decoded' => '', 'size_raw' => '',
		'size_decoded' => '', 'exploit' => '', 'js' => '', 'embed_file' => '', 'encrypted' => '', 'otype' => '',
		'parent_md5' => '', 'parent_sha256' => '', 'aa' => '',  'params_decoded' => '', 'objstm' => '',
		'filename_uncompressed' => '', 'size_uncompressed' => '');


$pdfhitTable = array('obj_id' => '', 'gen_id' => '', 'dup_id' => '', 'parent_md5' => '', 'parent_sha256' => '', 'exploit' => '',
		'exploittype' => '', 'exploitlocation' => '', 'searchtype' => '', 'shellcode' => '',
		'engine' => '', 'block' => '', 'partial' => '', 'block_filename' => '', 'hid' => '', 'hrank' => '');

$pdfsampleTable = array('ip' => '', 'mw_url' => '', 'mw_ip' => '', 'mw_time' => '', 'hits' => '',
		'filename' => '', 'md5' => '', 'sha1' => '', 'sha256' => '',
		'filesize' => '', 'content-type' => '', 'searchtype' => '', 'exploit' => '', 'exploittype' => '',
		'exploitlocation' => '', 'ssdeep' => '', 'completed' => '', 'engine' => '', 'new'=> '',
		'encrypted' => '', 'key' => '', 'encrypt_alg' => '', 'key_length' => '',
		'email' => '', 'message' => '', 'is_malware' => '', 'severity' => '',
		'reported' => '', 'summary' => '', 'private' => '',
		'has_js' => '', 'has_flash' => '', 'has_embed' => '', 'origfilename' => '');


function charset($string) {
	$char = mb_detect_encoding($string, "GB2312, Big5, UTF-8, EUC-JP");
	if ($char != '') {
		$ascii = mb_convert_encoding($string, "ASCII", $char);
		return $ascii;
	}
	return $string;
}


function jsmakePretty($dirty)
{
	$str = '';
	$instring = -1;
	$incomment = -1;
	$incomment2 = -1;
	$stringChar = '';


	for ($i = 0; $i < strlen($dirty)-1; $i++) {
		if ( $incomment ==-1 && $incomment2 ==-1 && $instring == -1 && ($dirty[$i] == '\'' || $dirty[$i] == '"') ) {
			$instring = $i;
			//echo "In String [$i]\n";
			$str .= $dirty[$i];
			$stringChar = $dirty[$i];
		} else if ($incomment ==-1 && $incomment2 ==-1&& $instring >=0 && $i+1 <= strlen($dirty) && $dirty[$i] == "$stringChar" && $dirty[$i-1] != '\\' ) {
			$instring = -1;
			//echo "End String [$i]\n";
			$str .= $dirty[$i];
			$stringChar = '';
		} else if ($incomment ==-1 && $incomment2 ==-1&& $i+1 <= strlen($dirty) && $instring == -1 && ($dirty[$i] == '/' && $dirty[$i+1] == '/') ) {
			$incomment = $i;
			//echo "In Comment 1 [$i]\n";
			//$str .= $dirty[$i];
			$i++;
			//$str .= $dirty[$i];
		} else if ($incomment ==-1 && $incomment2 ==-1&& $instring == -1 && ($dirty[$i] == '/' && $i+1 <= strlen($dirty) && $dirty[$i+1] == '*') ) {
			$incomment2 = $i;
			//echo "In Comment 2 [$i]\n";
			//$str .= $dirty[$i];
			$i++;
			//$str .= $dirty[$i];
		} else if ($incomment2 >= 0 && ($dirty[$i] == '*' && $dirty[$i+1] == '/') && $i+1 <= strlen($dirty)) {
			$incomment2 = -1;
			$instring = -1;
			//echo "End comment 2 [$i]\n";
			//$str .= $dirty[$i];
			$i++;
			//$str .= $dirty[$i];

		} else if ($incomment >= 0 && $dirty[$i] == "\n" ) {
			$incomment = -1;
			$instring = -1;
			//echo "End comment 1 [$i]\n";
			//$str .= $dirty[$i];
		} else if ($incomment >= 0 || $incomment2 >= 0) {
			//$str .= $dirty[$i];
		} else if ($incomment ==-1 && $incomment2 ==-1 && $instring == -1 && $dirty[$i] == ';' ) {
			$incomment = -1;
			//echo "add endline [$i]\n";
			$str .= $dirty[$i]."\n";;
 		} else if ($incomment ==-1 && $incomment2 ==-1 && $instring == -1 && $dirty[$i] == ' ' && $i+1 <= strlen($dirty) && ( $dirty[$i+1] == '{' ||
$dirty[$i+1] == '}' || $dirty[$i+1] == '(' || $dirty[$i+1] == ')' || $dirty[$i+1] == '=' || $dirty[$i+1] == '.' ||
$dirty[$i+1] == '\'' || $dirty[$i+1] == '"' || $dirty[$i+1] == '+' || $dirty[$i+1] == ' ')  ) {
			//$str .= $dirty[$i]."\n";
			//echo "test\n";
 		} else if ($incomment ==-1 && $incomment2 ==-1 && $instring == -1 && $dirty[$i] == ' ' && $i >= 1 &&( $dirty[$i-1] == ' ' || $dirty[$i-1] == '{' ||
$dirty[$i-1] == '}' || $dirty[$i-1] == '(' || $dirty[$i-1] == ')' || $dirty[$i-1] == '=' ||
$dirty[$i-1] == '\'' || $dirty[$i-1] == '"' || $dirty[$i-1] == '.' || $dirty[$i-1] == '+') ) {
			//$str .= $dirty[$i]."\n";;
		} else {
			$str .= $dirty[$i];
		}

	}

$arr = explode("\n", $str);
$str = '';
foreach ($arr as $line) {
	if ($line != '')
		$str .= trim($line)."\n";

};




  return $str;
}


function is_js($string) {

	//$str = jsmakePretty($string);
	$str = $string;


	$level = 0;
	$arr = explode(";\n", $str);
	$str = '';
	//$variables = array();
	foreach ($arr as $line) {
		$line = trim($line);
		if (strstr($line, '=') && strstr($line, 'var ') ) {
			//$arr2 = explode("=", $line, 2);
			//	echo "var = ".$arr2[0]."\n";
			//	echo "val = ".$arr2[1]."\n";

			//	$variables[str_replace('var ', '', $arr2[0])] = $arr2[1];
			$level++;
			//echo "var\n";
		} else if (preg_match("/function(\s*?)([a-zA-Z0-9_-]*?)(\s{0,25}?)\(/i", $line)) {
			$level++;
			//echo "funct\n";
		} else if (preg_match("/return /i", $line)) {
			$level++;
			//echo "return\n";
		} else if (preg_match("/try(\s*?)\{/i", $line)) {
			$level++;
			//echo "try\n";
		} else if (preg_match("/catch(\s*?)\{/i", $line)) {
			$level++;
			//echo "catch\n";
		} else if (preg_match("/replace(\s{0,3}?)\(/i", $line)) {
			$level++;
			//echo "replace\n";
		} else if (preg_match("/new Array/", $line)) {
			$level++;
			//echo "array\n";
		} else if (preg_match("/new Object/", $line)) {
			$level++;
			//echo "obj\n";
		} else if (preg_match("/new String(\s{0,3}?)\(/", $line)) {
			$level++;
			//echo "string\n";
		} else if (preg_match("/charAt(\s{0,3}?)\(/", $line)) {
			$level++;
			//echo "charat\n";
		} else if (preg_match("/^([a-zA-Z0-9_-]+?)=([a-zA-Z0-9_-]+?);$/", $line)) {
			$level++;
			//echo "format\n";
		} else if (preg_match("/substr(\s{0,3}?)\(/", $line)) {
			$level++;
			//echo "substr\n";
		} else if (preg_match("/app.viewerVersion/", $line)) {
			$level++;
			//echo "view\n";

		}
	}


	//var_dump($variables);

	return $level;
}


function scanStreams($result, $obj, $gen) {
	foreach ($result as $unique => $data) {
		if (isset($data['objstm']) && $data['objstm'] > 0) {
			if ((preg_match("/\/(#4a|J)(#61|a)(#76|v)(#61|a)(#53|S)(#63|c)(#72|r)(#69|i)(#70#p)(#74|t)\s+".$obj."\s+".$gen."\s+R/si", $data['parameters'])  ||  preg_match("/\/(#4a|J)(#53|S)\s+".$obj."\s+".$gen."\s+R/s", $data['parameters']))) {
				return 1;
			}
		}
	}
	return 0;
}

function analysePDF($file = array(), $sample_id = 0) {
	global $PDFstringSearch, $PDFhexSearch, $global_block_encoding, $global_engine, $pdfdir, $global_store_files, $global_export_all, $global_yara_sig;

	$md5 = $file['md5'];

	logDebug($file['md5']." start processing");

	$file_raw = file_get_contents($file['filename']);
	logDebug($file['md5']." end processing");

	$yara_result = array();


	$fileUpdate = array('exploit' => 0, 'hits' => 0, 'completed' => 1, 'is_malware' => 0, 'summary' => '', 'severity' => 0);


	$header = substr($file_raw, 0, 1024);
	if (preg_match("/ns.adobe.com\/xdp/si", $header)) {
		//process xdp format
		preg_match("/<chunk>(.*?)<\/chunk>/si", $file_raw, $matchF);
		if (isset($matchF[1])) {
			$intermediate = base64_decode($matchF[1]);
			if ($intermediate != '')
				$file_raw = $intermediate;
		}

	}
	$header = substr($file_raw, 0, 1024);
	if (!preg_match("/%PDF/si", $header)) {
		echo "File missing PDF signature - not processed.\n";
		$fileUpdate['not_pdf'] = 1;
		return $fileUpdate;
	}



	//yara original file
	if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
		$yhits = yara_wrapper_file($file['filename']);
		foreach ($yhits as $k => $v) {
			array_push($yara_result, $k);
		}
	}


	$result = pdfSlice($file_raw);



	//store encryption metadata
	if (isset($result['document']['encrypted']) && $result['document']['encrypted'] > 0) {
		$fileUpdate['encrypted'] = 1;
		$fileUpdate['key'] = $result['document']['key'];
		//if ($result['document']['v'] == 4)
			$fileUpdate['encrypt_alg'] = $result['document']['v'];
		//else
			//$fileUpdate['encrypt_alg'] = "RC4";
		$fileUpdate['key_length'] = $result['document']['key_length'];

	}


	$summaryA = array();

	//objstm section
	$newobjs = array();
	foreach ($result as $unique => $data) {
		if ($unique != 'document') {
			if (isset($data['parameters']) && preg_match("/(#4F|O)(#62|b)(#6a|j)(#53|S)(#74|t)(#6d|m)/si", $data['parameters']) ) {
				//check for ObjStm
				$data['otype'] = "ObjStm";
				$newobj = parseObjStm($data['parameters'], $data['decoded']);
				foreach ($newobj as $uniquel => $datal) {
					$datal['objstm'] = $data['object'];
					$datal['dup_id'] += $data['dup_id'];
					$datal['atype'] = "objstm";
					$result[$uniquel] = $datal;
				}
				//print_r( $newobj);

				//$newobjs = array_merge($newobjs, $newobj);
				//print_r($newobjs);
			}
		}
	}
	//$result = array_merge($result, $newobjs);
	//print_r($result);
	//objstm  endsection

	foreach ($result as $unique => $data) {

		if ($unique != 'document') {


			//scan for malware


			$malware = array('found' => 0);


			logDebug($file['md5']."obj ".$data['object']." raw");

			$d = '';
			if (isset($data['decoded']))
				$d = $data['decoded'];

			//uncompress flash
			if (preg_match("/^CWS(.{1}?)/s", $d)) {
				$uncompressed = flashExplode($d);
				$unmd5 = md5 ($uncompressed);
				if ($uncompressed != '') {
					if (!isset($global_store_files) || $global_store_files != 0) {
						if (!file_exists($pdfdir.$file['md5']."/"))
							mkdir($pdfdir.$file['md5']."/");
						file_put_contents($pdfdir.$file['md5']."/obj-".$data['object']."-gen-".$data['generation']."-dup-".$data['dup_id']."-".$unmd5.".flash", $uncompressed);
						$data['filename_uncompressed'] = $pdfdir.$file['md5']."/".$unmd5.".flash";
					}
					$data['size_uncompressed'] = strlen($uncompressed);
				}

				$malware = javascriptScan($malware, $uncompressed, $PDFstringSearch, $PDFhexSearch);
				if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '')  ) {
					$malware['javascript'] = $uncompressed;

				}



				//yara exploded flash
				if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
					$yhits = yara_wrapper($uncompressed );
					foreach ($yhits as $k => $v) {
						array_push($yara_result, $k);
					}
				}

				unset($uncompressed);

			}


			//original
			$malware = javascriptScan($malware, $d, $PDFstringSearch, $PDFhexSearch);

			if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '')  ) {
				$malware['javascript'] = $d;

			}

			//yara decoded objects
			if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
				$yhits = yara_wrapper($d);
				foreach ($yhits as $k => $v) {
					array_push($yara_result, $k);
				}
			}

			//check for overflow
			if (strlen($d) < 10000000) {

				//correct for unicode
				//$d = charset($d);
				$d = str_replace("\x00", "", $d); //turf unicode here

				$malware = javascriptScan($malware, $d, $PDFstringSearch, $PDFhexSearch);
				if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '')  ) {
					$malware['javascript'] = $d;

				}

				//correct for hexcodes
				$df = findHiddenJS($d);
				logDebug($file['md5']."obj ".$data['object']." hex");

				$malware = javascriptScan($malware, $df, $PDFstringSearch, $PDFhexSearch);
				if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '') ) {
					$malware['javascriptencoding'] = $global_block_encoding;
				}
				unset($df);
				logDebug($file['md5']."obj ".$data['object']." unicode");


				//correct for unicode
				$df = decode_replace($d);
				$df = unicode_to_shellcode($df);
				//echo "JSEnc2: $df\n";
				$malware = javascriptScan($malware, $df, $PDFstringSearch, $PDFhexSearch);
				if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '') ) {
					$malware['javascript'] = $df;
				}
				unset($df);
				logDebug($file['md5']."obj ".$data['object']." blocks");

			} else {
				$malware[$pattern.uniqid('', TRUE)] = array ('searchtype' => 'pdfoverflow', 'matching' => 'full', 'keylength' =>  0, 'key' => '',
						'search' => 'size', 'location' => 0, 'top'=>0,  'keycount' => 0, 'keysum' => '',
						'keylocation' => 0, 'keyaccuracy' => 0, 'searcherrors' => 0, 'virustype' => 'warning block size over 10MB',
						'block' => '', 'block_is_decoded' => 1, 'block_encoding' => 'plain',
						'block_size' => strlen($d), 'block_type' => 'unknown',
						'block_md5' => md5($d), 'block_sha1' => sha1($d),
						'block_sha256' => hash('sha256', $d),
						'block_encoding' => $global_block_encoding,
						'rawlocation' => 0, 'rawblock' => '','rawclean' => '');
				$malware['found'] = 1;

			}

			//blockhashes for flash etc
			if (isset($data['md5_raw'])) {
				$ret = checkBlockHash($data['md5_raw']);
				if ($ret['found'] == 1) {
					$malware = array_merge($ret, $malware);
					//echo "blocka\n";
					$malware['found'] = 1;
				} else if (isset($data['md5'])) {
					$ret = checkBlockHash($data['md5']);
					if ($ret['found'] == 1) {
						$malware = array_merge($ret, $malware);
						//echo "blockb\n";
						$malware['found'] = 1;
					}
				}
			} else if (isset($data['md5'])) {
				$ret = checkBlockHash($data['md5']);
				if ($ret['found'] == 1) {
					$malware = array_merge($ret, $malware);
					//echo "blockc\n";
					$malware['found'] = 1;
				}
			}

			logDebug($file['md5']."obj ".$data['object']." params");


			//run scan on params for colors overflow etc
			if (isset($data['parameters']) && $data['parameters'] != '') {
				$malware = javascriptScan($malware, $data['parameters'], $PDFstringSearch, $PDFhexSearch);

				if (isset($result['document']['encrypted'])) {
					//yara decrypted params
					if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
						$yhits = yara_wrapper($data['parameters']);

						foreach ($yhits as $k => $v) {
							array_push($yara_result, $k);
						}
					}


				}

			}


			$pdfobj = array('obj_id' => $data['object'], 'gen_id' => $data['generation'],
				'params' => $data['parameters'], 'dup_id' => $data['dup_id'],
				'parent_md5' => $file['md5'], 'parent_sha256' => $file['sha256']);

			if (isset($data['filename_uncompressed']) ) {
				$pdfobj['filename_uncompressed'] = $data['filename_uncompressed'];
				$pdfobj['size_uncompressed'] = $data['size_uncompressed'];


			}

			logDebug($file['md5']."obj ".$data['object']." save hits");



			if ($malware['found'] >= 1) {
				$pdfobj['exploit'] = 1;
				$fileUpdate['exploit'] = 1;
				$fileUpdate['hits']++;
				foreach ($malware as $search => $hitraw) {
					if(is_array($hitraw)) {
						//echo $hitraw['virustype'];
						$hit = array('obj_id' => $data['object'], 'gen_id' => $data['generation'], 'dup_id' => $data['dup_id'],
							'parent_md5' => $file['md5'], 'parent_sha256' => $file['sha256'], 'exploit' => 1,
							'exploittype' => $hitraw['virustype'], 'exploitlocation' => $hitraw['location'], 											'searchtype' => $hitraw['searchtype'],
							'engine' => $global_engine, 'block' => $hitraw['block']);
						if (stristr($hitraw['block_type'], 'shellcode'))
							$hit['shellcode'] = 1;
						/*if (stristr($hitraw['block_type'], 'javascript')) //hits on flash as well
							$pdfobj['js'] = 1;*/
						if (isset($hitraw['rawblock']))
							$hit['partial'] = $hitraw['rawblock'];

						if (stristr($hitraw['virustype'], 'javascript in XFA block') )
							$pdfobj['js'] = 1;

						if (stristr($hitraw['virustype'], 'CVE-')  && !stristr($hitraw['virustype'], 'CVE-2009-0658') )
							$fileUpdate['severity'] += 10;
						else
							$fileUpdate['severity'] += 1;


						//$fileUpdate['summary'] .= $hit['obj_id'].".".$hit['gen_id']."@".$hit['exploitlocation'].": ".$hit['exploittype']."\n";
						$summaryA[$hit['obj_id'].".".$hit['gen_id']."@".$hit['dup_id'].$hit['exploittype']] = $hit['obj_id'].".".$hit['gen_id']."@".$hit['dup_id'].": ".$hit['exploittype']."\n";
					}
				}
			}






			if (isset($data['key']))
				$pdfobj['key'] = $data['key'];
			if (isset($data['filter']))
				$pdfobj['filters'] = $data['filter'];
			if (isset($data['atype']) && $data['atype'] == 'js')
				$pdfobj['js'] = 1;
			if (!isset($pdfobj['js']) && isset($data['decoded'])) {
				$dat = str_replace("\x00", "", $data['decoded']);
				//echo $data['object']."\n";
				$level = is_js($dat);
				if ($level > 1)
					$pdfobj['js'] = $level;
			}


			if (!isset($pdfobj['js']) &&  (preg_match("/\/(#4a|J)(#61|a)(#76|v)(#61|a)(#53|S)(#63|c)(#72|r)(#69|i)(#70#p)(#74|t)\s+".$data['object']."\s+".$data['generation']."\s+R/si", $file_raw)  ||  preg_match("/\/(#4a|J)(#53|S)\s+".$data['object']."\s+".$data['generation']."\s+R/s", $file_raw))) {
				$pdfobj['js'] = 1;
			}

			if (!isset($pdfobj['js']) &&  preg_match("/\/(#4a|J)(#53|S)\s+\(/s", $data['parameters']) ) {
				$pdfobj['js'] = 1;
			}

			if (!isset($pdfobj['js']) && scanStreams($result, $data['object'], $data['generation']) == 1)
				$pdfobj['js'] = 1;


			if (isset($data['parameters']) && preg_match("/(#61|a)(#70|p)(#70|p)(#6c|l)(#69|i)(#63|c)(#61|a)(#74|t)(#69|i)(#6f|o)(#6e|n)\s*(#2F|\/)\s*(#70|p)(#64|d)(#66|f)/si", $data['parameters']) ) {
				//should grab the embedded pdf
				$pdfobj['embed_file'] = 1;
				logDebug($file['md5']."obj ".$data['object']." has embedded pdf");

			} //could do alt check for embedded pdfs with header


			if (isset($data['otype']) && $data['otype'] != '')
				$pdfobj['otype'] = $data['otype'];


			if (isset($data['parameters']) && preg_match("/(#4F|O)(#62|b)(#6a|j)(#53|S)(#74|t)(#6d|m)/si", $data['parameters']) ) {
				//check for ObjStm
				$pdfobj['otype'] = "ObjStm";
			}




			if (isset($result['document']['encrypted'])) {
				$pdfobj['encrypted'] = $result['document']['encrypted'];

			} else
				$pdfobj['encrypted'] = 0;

			if (isset($data['stream']) && $data['stream'] != '') {
				$pdfobj['md5_raw'] = $data['md5_raw'];
				if (!isset($global_store_files) || $global_store_files != 0) {
					if (!file_exists($pdfdir.$file['md5']."/"))
						mkdir($pdfdir.$file['md5']."/");
					file_put_contents($pdfdir.$file['md5']."/obj-".$data['object']."-gen-".$data['generation']."-dup-".$data['dup_id']."-".$data['md5_raw'].".stream", $data['stream']);
					$pdfobj['filename_raw'] = $pdfdir.$file['md5']."/".$data['md5_raw'].".stream";
				}
				$pdfobj['size_raw'] = strlen($data['stream']);
			}

			if (isset($data['decoded']) && $data['decoded'] != '') {
				$pdfobj['md5_decoded'] = $data['md5'];
				if (!isset($global_store_files) || $global_store_files != 0) {
					if (!file_exists($pdfdir.$file['md5']."/"))
						mkdir($pdfdir.$file['md5']."/");
					file_put_contents($pdfdir.$file['md5']."/obj-".$data['object']."-gen-".$data['generation']."-dup-".$data['dup_id']."-".$data['md5'].".stream", $data['decoded']);
				}
				$pdfobj['filename_decoded'] = $pdfdir.$file['md5']."/".$data['md5'].".stream";
				$pdfobj['size_decoded'] = strlen($data['decoded']);
			}


			//process embedded PDF
			if (isset($pdfobj['embed_file']) && $pdfobj['embed_file'] == 1) {
				if (isset($data['decoded']) && $data['decoded'] != '') {
					logDebug($file['md5']."obj ".$data['object']." check pdf header");
					if (preg_match("/%PDF/si", $data['decoded'])) {
						logDebug($file['md5']."obj ".$data['object']." run embedded ".$pdfobj['filename_decoded']);

						//$sub = ingest($pdfobj['filename_decoded']);
						if (isset($sub['severity']))
							$fileUpdate['severity'] += $sub['severity'];
					}

				}

			}


			if (isset($pdfobj['js']) && $pdfobj['js'] > 0)
				$fileUpdate['severity'] += 1;


			if ($fileUpdate['severity'] > 0)
				$fileUpdate['is_malware'] = 1;

			if (isset($pdfobj['js']) && $pdfobj['js'] > 0)
				$summaryA[$pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id']."js"] = $pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id'].": suspicious.warning: object contains JavaScript\n";

			if (isset($pdfobj['embed_file']) && $pdfobj['embed_file'] == 1)
				$summaryA[$pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id']."pdf"] = $pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id'].": suspicious.warning: object contains embedded PDF\n";


			if (isset($pdfobj['size_raw']) && isset($pdfobj['size_decoded']) && $pdfobj['size_raw'] > 0 && $pdfobj['size_decoded'] == 0)
				$summaryA[$pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id']."dc"] = $pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id'].": suspicious.warning: object not decoded\n";



			logDebug($file['md5']."obj ".$data['object']." end");

		}

	}

	//grab EOF
	logDebug($file['md5']."obj extract eof ");

	if (preg_match_all("/(\x25\x25EOF)/s", $file_raw, $matches, PREG_OFFSET_CAPTURE) ) {
		$occ = count($matches[0]);
		$lastloc = $matches[0][$occ-1][1]+5;
		$enddata = trim(substr($file_raw, $lastloc), "\x0A\x0D");
		if ($enddata != '' ) {


			logDebug($file['md5']."obj extract eof 2");


				$pdfobj = array('obj_id' => -1, 'gen_id' => -1,
					'params' => 'Extracted from end of file', 'dup_id' => $lastloc,
					'parent_md5' => $file['md5'], 'parent_sha256' => $file['sha256']);
				$pdfobj['md5_raw'] = md5($enddata);
				if (!isset($global_store_files) || $global_store_files != 0) {
					if (!file_exists($pdfdir.$file['md5']."/"))
						mkdir($pdfdir.$file['md5']."/");
					file_put_contents($pdfdir.$file['md5']."/obj-".$data['object']."-gen-".$data['generation']."-dup-".$data['dup_id']."-".$pdfobj['md5_raw'].".stream", $enddata);
					$pdfobj['filename_raw'] = $pdfdir.$file['md5']."/".$pdfobj['md5_raw'].".stream";
				}
					$pdfobj['size_raw'] = strlen($enddata);


				if ($pdfobj['obj_id']== -1 && $pdfobj['size_raw'] > 128)
					$summaryA[$pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id']."ss"] = $pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id'].": suspicious.warning: end of file contains content\n";



				logDebug($file['md5']."obj save eof ");

		}

	}


	foreach ($summaryA as $key => $value) {
		$fileUpdate['summary'] .= $value;
	}


	$fileUpdate['engine'] = $global_engine;

	if (isset($global_export_all) && $global_export_all == 1)
		$fileUpdate['export_all'] = $result;


	if (count($yara_result) > 0)
		$fileUpdate['yara'] = array_unique($yara_result);

	return $fileUpdate;

}


function parseObjStm($params, $stream) {
	$n = 0;
	$out = array();

	if (preg_match("/(#4E|N)\s+(\d+)/s", $params, $res) ) {

		$n = $res[2];
		//echo "N=$n\n";
	}


	$first = 0;
	if (preg_match("/(#46|F)(#69|i)(#72|r)(#73|s)(#74|t)\s+(\d+)/s", $params, $res2) ) {

		$first = $res2[6];
		//echo "First=$first\n";
	}

	$header = substr($stream, 0, $first-1);
	//echo "Header=$header\n";

	preg_match_all("/(\d+)\s+(\d+)/s", $header, $resh);

	//print_r($resh);
	if(isset($resh[1]) ) {
		for ($i=0; $i < count($resh[1]); $i++) {
			//echo "Obj=".$resh[1][$i]." loc=".($resh[2][$i]+$first);
			if ($i+1 >= count($resh[1])) {
				$end = strlen($stream);
				//echo " End=".$end;
			} else {
				$end = $resh[2][$i+1]+$first-1;
				//echo " End=".$end;
			}

			//echo "\n";
			$ident = $resh[1][$i].".0.".($resh[2][$i]+$first);
			$out[$ident] = array('object' =>  $resh[1][$i], 'generation' => '0', 'obj_id' =>  $resh[1][$i], 'gen_id' => '0', 'dup_id' => ($resh[2][$i]+$first));


			//split params and stream
			$out[$ident]['parameters'] = substr($stream, $resh[2][$i]+$first, $end-$resh[2][$i]-$first);
		}

	}

	return $out;
}




?>
