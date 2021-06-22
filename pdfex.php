<?PHP
/*
 * v3.0 Jun 1 2016
 * pdfex.php: tyLabs.com PDFExaminer - command line script
 * Main script to call for command line usage: 
 * php pdfex.php <filename> [data element to display/defaults to
 * all when blank]
 */

//yara executable and signatures
$global_yara_cmd = '/opt/local/bin/yara';
$global_yara_sig = '';


ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_COMPILE_ERROR|E_ERROR|E_CORE_ERROR);
date_default_timezone_set('America/Toronto');


include_once('pdfex-cli.php');
include_once('pdfex-lib.php');


if (!isset($PDFstringSearch)) {
	echo "ERROR: Signatures not found. pdfex-sig.php is probably corrupt.\n";
	exit(0);
}


if (!isset($argv[1])) {
	echo "Please specify a file or directory to process\n";
	exit(0);
}

$jsonout = 0;

$options = getopt("p:yvj", array("json", "yara:", "yarasig:","version","info","password:"));

if (isset($options['p']))
	$global_userpass = $options['p'];
if (isset($options['password']))
	$global_userpass = $options['password'];

if (isset($options['j']) || isset($options['json']))
	$jsonout = 1;
if (isset($options['y']) )
	$global_yara_sig = $options['y'];
if (isset($options['yarasig']) )
	$global_yara_sig = $options['yarasig'];
if (isset($options['yara']) )
	$global_yara_cmd = $options['yaracmd'];
if (isset($options['version']) || isset($options['v']) || isset($options['info'])) {
	echo "pdfex.php <-y yarasig> <-p decryp pass> <file or dir>\n";
		if (!isset($global_engine) ) {
			echo "ERROR: Signatures not found.\n";
			exit(1);
		} 
		echo "Detection engine: $global_engine\n";
		echo "PDF string signatures: ".count($PDFstringSearch)."\n";
		echo "PDF hex signatures: ".count($PDFhexSearch)."\n";
		echo "PDF object hashes: ".count($PDFblockHash)."\n";
}

$file = array();
$dir = array();
$opt = array();
for ($i = 1; $i < $argc; $i++) {
	if ($argv[$i] == "-y" ||$argv[$i] == "--yara" ||$argv[$i] == "--yarasig" ||$argv[$i] == "--password" ||$argv[$i] == "-p") {
		$i++;
	} else if ($argv[$i] == "-v" || $argv[$i] == "--version" || $argv[$i] == "--info" ||$argv[$i] == "-j" ||$argv[$i] == "--json") {
		continue;
	} else if (is_file($argv[$i])) {
		$file[$argv[$i]] = 1;
	} else if (is_dir($argv[$i])) {
		$dir[$argv[$i]] = 1;
	} else
		$opt[$argv[$i]] = 1;
}



foreach ($file as $f => $x) {


	$filedat = array ('filename' => $f, 'md5' => md5_file($f), 'sha256' => '');

	$result = analysePDF($filedat);

	if (isset($result['yara']) && is_array($result['yara'])) {
		$yara = '';
		foreach($result['yara'] as $sig) {
			if ($sig != '')
				$yara .= "$sig\n";
		}
		$result['yara'] = $yara;
	}
			

	if (count($opt) > 0) {
		foreach ($opt as $o => $y) {
			if (isset($result[$o])) {
				if ($argc > 2)
					echo $o."=";
				if (!is_array($result[$o]))
					echo $result[$o]."\n";
				else {
					foreach ($result[$o] as $item) {
						echo "$item\n";
					}
				}

			}
		}
	} else {
		
		if ($jsonout != 1) 
			print_r($result);
		else
			echo json_encode($result, JSON_PRETTY_PRINT);
	}
}

foreach ($dir as $d => $z) {
  if (false !== ($listing = scandir($d))) {
    foreach ($listing as $id => $file) {
        if ($file != "." && $file != ".." && $file != ".DS_Store" && is_file($d."/".$file) && 
		strtolower(end(explode(".", $file))) != 'txt' && 
		strtolower(end(explode(".", $file))) != 'php') {
			if ($jsonout != 1) 
				echo $d."/".$file."\n";
			$filedat = array ('filename' => $d."/".$file, 'md5' => md5_file($d."/".$file), 'sha256' => '');

			$result = analysePDF($filedat);
			if (isset($result['yara']) && is_array($result['yara'])) {
				$yara = '';
				foreach($result['yara'] as $sig) {
					if ($sig != '')
						$yara .= "$sig\n";
				}
				$result['yara'] = $yara;
			}

		if (count($opt) > 0) {
			foreach ($opt as $o => $y) {
				if (isset($result[$o])) {
					if ($argc > 2)
						echo $o."=";
					if (!is_array($result[$o]))
						echo $result[$o]."\n";
					else {
						foreach ($result[$o] as $item) {
							echo "$item\n";
						}
					}
	
				}
			}
		} else {
			
		
		if ($jsonout != 1) 
			print_r($result);
		else
			echo json_encode($result, JSON_PRETTY_PRINT);
		}
        }
    }
  }
    closedir($handle);
}




//optional debugging handlers
function logdebug($string) {
	//echo $string."\n";
}
function logverbose($string) {
	//echo $string."\n";
}

?>
