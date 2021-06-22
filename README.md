# PDFExaminer Tool - Analyse PDF Malware

## PDFExaminer Command Line Scanner

This document describes installation and usage of the PDF Examiner – command line version.
The PDFExaminer command line scanner is a compact PHP library to process PDF documents for decompression, decryption, and deobfuscation, to scan for known exploits and identify suspicious elements of new threats.

## Requirements

PHP 5.0 or greater, tested up to 7.0. PHP 5 requires modules php5-hash, php5-ctype, php5-mcrypt and php5-zlib. PHP7 requires only php70-mcrypt
512MB RAM, 1GB Recommended

## Recommended

For safe handling of MS Windows based exploits, Linux or Mac OSX is recommended.
Yara - malware classification -  http://plusvic.github.io/yara/
LibEmu - to detect Windows shellcode - http://libemu.carnivore.it/
NASM - to disassemble Windows shellcode - http://www.nasm.us/

## Package Contents

pdfex-cli.php: command line related functions
pdfex-lib.php: PDFExaminer engine
pdfex-sig.php: detection signatures
pdfex.php: command line script


## Installation
Copy the PHP files to an accessible directory. It is not necessary to make the files executable.

## Running PDF Examiner on the command line

Use the pdfex.php to specify a PDF file or directory of PDF files to process:
php pdfex.php file_to_process.pdf

## Command line options

php pdfex.php <-p user password> file_to_process.pdf
-p option to specify decrypting using a user password.

php pdfex.php <-y yara include> file_to_process.pdf
-y option to specify a Yara signature include file.

php pdfex.php file_to_process.pdf <hits>
Returns the number of positive signature hits

php pdfex.php file_to_process.pdf <is_malware>
Returns binary result of scan 0 for clean 1 for malware

php pdfex.php file_to_process.pdf <summary>
Returns a texual reporting of suspect PDF  by object and generation

php pdfex.php file_to_process.pdf <severity>
Returns a weighted severity of detected entities >10 is considered malware, however, one point is assigned per JavaScript containing object, potentially causing a false positive effect on complex JavaScript containing documents.


Brackets should be omitted in the actual command line option.

Chain multiple queries together to create your own custom output.

## Advanced Options

The following PHP variables in pdfex-cli.php correspond to the following advanced capabilities:

$global_store_files = 1;  Save objects of the PDF file in the $pdfdir directory of the named for the MD5 of the current file. The naming convention used is <PDF MD5>/ obj-<PDF object ID>-gen-<PDF Generation ID>-dup<file offset in bytes to identify duplicate obj/gen  combinations>-<stream MD5>

$pdfdir = ‘<directory>’; Location where extracted objects can be saved.

The following options can be set in pdfex.php:
$global_yara_cmd=/path/to/yara;  Yara executable.

$global_yara_sig=/path/to/yarainclude.rar;  Yara include file with signatures to scan for.

