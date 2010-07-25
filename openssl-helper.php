#!/usr/bin/php
<?php
  error_reporting(E_ERROR | E_WARNING | E_PARSE);
  define('MSG_DEBUG',   1);
  define('MSG_VERBOSE', 2);
  define('MSG_WARNING', 4);
  define('MSG_ERROR',   8);

  if (in_array('--help', $argv)) {
    echo "  Usage: ".basename($argv[0])." STANDARD-COMMAND [OPTIONS] [openssl OPTIONS] [--recursive=(Yes/no)] [--strict=(Yes/no)] [--keep-original=(yes/No)] [--encrypted-extension=EXTENSION] <path> [<path> [<path> [..]]]

  OPTIONS:
    --help                    Display help screen then quit.
    --version                 Display version of openssl-helper script.
    --verbose                 Enable verbose mode.
    --recursive=[Yes/no]      Recursively search for files under the paths provided.
    --strict=[Yes/no]         Only perform encryption/descryption routines on files with
                              appropriately corresponding extensions.
                              i.e. Only encrypt files without or only decrypt files with
                              an extension corresponding to the cipher being passed to
                              openssl.
    --keep-original=[yes/No]  Keep the original unencrypted files; default is No.
    --encrypted-extension     Extension of files considered encrypted, or the extension to
                              to give to newly encrypted files.  This option, if not
                              present, will default to the name of the cipher being used
                              for the encryption.
    --pretend                 Don't perform any file actions, instead output the commands
                              that would be called.

  openssl OPTIONS:
    See 'openssl enc -h' for a list of 'openssl OPTIONS'.

  Example(s):
    * Encrypt recursively with DES3 and keep the original unencrypted
      file(s) from /root/
        {$argv[0]} enc -e -des3 -salt --keep-original=yes /root/ -pass pass:password
    * Encrypt with Blowfish, removing the original unencrypted file(s),
      only the files directly in /tmp/ (non-recursive)
        {$argv[0]} enc -e -bf -salt --recursive=no /tmp/ -pass pass:password
    * Decrypt with DES3, removing the original encrypted file(s),
      only the files directly in /tmp/ (non-recursive)
        {$argv[0]} enc -d -des3 -salt --recursive=no /root/ -pass pass:password
";
    exit(0);
  }

  if (in_array('--version', $argv)) { echo "  openssl-helper build.20060319\n"; exit(0); }
  if (in_array('--verbose', $argv)) $verbose = true;
  if (in_array('--debug',   $argv)) $debug   = true;
  if (in_array('--pretend', $argv)) $pretend = true;
  if (in_array('--force',   $argv)) $force   = true;
  $encdec = new secure;

  if (empty($encdec->config['openssl-helper']['cipher'])) error("No cipher specified.");
  if (empty($encdec->config['openssl-helper']['standard-command'])) error("No 'standard command' specified.  See 'openssl list-standard-commands' for more information.");
  if (!$encdec->is_standard_command($encdec->config['openssl'][0]) && !$force) error("First openssl passthru argument is not a standard-command.  This is probably not desirable.  Use --force option to continue anyways.");
  if ($encdec->config['openssl-helper']['standard-command'] == 'enc' && empty($encdec->config['openssl-helper']['mode']) && !$force) error("No method provided for use with the 'enc' standard-command.  This is probably not desirable; you should probably add -e for encrypt or -d for decrypt.  Use --force option to continue anyways.");

  error(var_export($encdec->config, true), MSG_DEBUG);
  error("openssl passthru: ".$encdec->passthru(), MSG_DEBUG);

  if (is_array($encdec->config['file'])) {
    foreach ($encdec->config['file'] as $file) {
      traverse($file, true);
    }
  } else {
    error("No files specified.");
  }

  function traverse($loc, $root = false) {
    error("traverse($loc);", MSG_DEBUG);
    global $encdec, $stats, $pretend;
    if (empty($loc)) return false;

    if (is_file($loc)) {
      if (!is_readable($loc)) {
        echo "Skipping '$loc' because file is unreadable.\n";
        $stats['skipped']++;
        return true;
      }

      $details = pathinfo($loc);
      if (softbool($encdec->config['openssl-helper']['strict'])) {
        if (
          ($encdec->config['openssl-helper']['mode'] == 'encrypt' && strtolower($details['extension']) == strtolower($encdec->config['openssl-helper']['encrypted-extension'])) ||
          ($encdec->config['openssl-helper']['mode'] == 'decrypt' && strtolower($details['extension']) != strtolower($encdec->config['openssl-helper']['encrypted-extension']))
        ) {
          echo "Skipping '$loc' per strict rule.\n";
          $stats['skipped']++;
          return true;
        }
      }
      $out = ($encdec->config['openssl-helper']['mode'] == 'decrypt') ? rawrtrim($loc, '.'.$encdec->config['openssl-helper']['encrypted-extension']) : $loc.'.'.$encdec->config['openssl-helper']['encrypted-extension'];
      if (file_exists($out)) {
        echo "Skipping '$loc' because output file already exists.\n";
        $stats['skipped']++;
        return true;
      }
      error("openssl ".$encdec->passthru()." -in ".escapeshellarg($loc)." -out ".escapeshellarg($out), MSG_VERBOSE);
      echo "Processing '$loc' ... ";
      if (!$pretend) {
        exec("openssl ".$encdec->passthru()." -in ".escapeshellarg($loc)." -out ".escapeshellarg($out), $output, $returned);
        error("openssl return code: $returned", MSG_DEBUG);
        if ($returned !== 0) {
          if (file_exists($out)) {
            error("Cleaning up failed openssl process.", MSG_VERBOSE);
            error("rm '$out'", MSG_DEBUG);
            unlink($out);
          }
          error("OpenSSL call failed.");
        } else {
          echo "Done\n";
        }
      } else {
        echo "Pretend\n";
      }
      $stats['success']++;
      if (!softbool($encdec->config['openssl-helper']['keep-original'])) {
        if ($pretend) {
          echo "  rm '$loc'\n";
        } else {
          error("Deleting '$loc' ...", MSG_VERBOSE);
          if (!unlink($loc)) error("Unable to delete '$loc'.");
        }
      }
    } elseif (is_dir($loc)) {
      if (softbool($encdec->config['openssl-helper']['recursive']) || $root) {
        if ($dh = opendir($loc)) {
          while (($file = readdir($dh)) !== false) {
            if ($file != '.' && $file != '..') $list[] = $file;
          }
          if (!empty($list)) {
            foreach ($list as $item) {
              traverse(folder($loc).$item);
            }
          }
        } else {
          echo "Skipping directory '$loc' because failed to open.\n";
          return true;
        }
      }
    } else {
      echo "Skipping '$loc' because is of unknown type.\n";
      return true;
    }
  }



  class secure {
    var $config;
    var $standard_commands;
    var $ciphers;

    function __constructor() {
      $this->secure();
    }

    function secure() {
      // defaults
      $this->config['openssl-helper']['strict']        = 'yes';
      $this->config['openssl-helper']['recursive']     = 'yes';
      $this->config['openssl-helper']['keep-original'] = 'no';

      // command line settings
      $this->options();
      if (isset($this->config['openssl-helper']['cipher']) && !isset($this->config['openssl-helper']['encrypted-extension']))
         $this->config['openssl-helper']['encrypted-extension'] = $this->config['openssl-helper']['cipher'];
    }

    function options() {
      global $argv, $argc;
      for ($i = 1; $i < $argc; $i++) {
        if (substr($argv[$i], 0, 2) == '--' && strlen($argv[$i]) > 2) { // openssl-helper option
          list($var, $val) = explode('=', substr($argv[$i], 2));
          if (!empty($var) && !empty($val)) $this->config['openssl-helper'][$var] = $val;
        } elseif (substr($argv[$i], 0, 5) == '-pass' && $i+1 < $argc) { // special openssl passthru (attaches to it's following argument)
          $this->config['openssl'][] = $argv[$i].' '.escapeshellarg($argv[$i+1]);
          $i++;
        } elseif ((substr($argv[$i], 0, 1) == '-' && substr($argv[$i], 1, 1) != '-' && strlen($argv[$i]) > 1) || $this->is_standard_command($argv[$i])) { // openssl passthru
          if ($argv[$i] == '-e') {
            $this->config['openssl-helper']['mode'] = 'encrypt';
          } elseif ($argv[$i] == '-d') {
            $this->config['openssl-helper']['mode'] = 'decrypt';
          } elseif ($this->is_cipher(substr($argv[$i], 1))) {
            $this->config['openssl-helper']['cipher'] = substr($argv[$i], 1);
          } elseif ($this->is_standard_command($argv[$i])) {
            $this->config['openssl-helper']['standard-command'] = $argv[$i];
          }
          $this->config['openssl'][] = $argv[$i];
        } else { // file/directory
          if ($path = realpath($argv[$i])) $this->config['file'][] = $path;
        }
      }
      return true;
    }

    function is_standard_command($command) {
      if (empty($command)) return false;
      if (empty($this->standard_commands)) {
        $this->standard_commands = explode("\n", trim(`openssl list-standard-commands`, "\n")); // TO DO: perform exec() instead and check if command was successful
      }
      if (!is_array($this->standard_commands)) return false;
      return in_array($command, $this->standard_commands);
    }

    function is_cipher($argument) {
      if (empty($argument)) return false;
      if (empty($this->ciphers)) {
        $this->ciphers = explode("\n", trim(`openssl list-cipher-commands`, "\n")); // TO DO: perform exec() instead and check if command was successful
      }
      if (!is_array($this->ciphers)) return false;
      return in_array($argument, $this->ciphers);
    }

    function passthru() {
      if (!is_array($this->config['openssl'])) return false;
      return implode(' ', $this->config['openssl']);
    }
  }



  /**
  * Ensures that specified path is represented as a folder (ensures existence of a trailing slash)
  *
  * @param      path       String   Path
  * @return     path       String   Returns path with trailing slash
  **/
  function folder($path) {
    if (empty($path)) return '';
    if (substr($path, -1) != '/') $path .= '/';
    return $path;
  }

  function softbool($var) {
    switch (gettype($var)) {
      case 'boolean': return $var;
      case 'integer': return ($var != 0);
      case 'double':  return ($var != 0);
      case 'string':  return (strtolower($var) == 'y' || strtolower($var) == 'yes' || strtolower($var) == 'true');
      default: return (bool) $var;
    }
  }

  function rawrtrim($string, $trim) {
    if (substr($string, -(strlen($trim))) == $trim) return substr($string, 0, strlen($string) - strlen($trim)); else return $string;
  }

  function error($message, $level = MSG_ERROR) {
    global $verbose, $debug;
    switch ($level) {
      case MSG_ERROR:
        echo "  Error: $message\n";
        exit(1);
      case MSG_WARNING:
        echo "  Warning: $message\n";
        break;
      case MSG_VERBOSE:
        if ($verbose) echo "  $message\n";
        break;
      case MSG_DEBUG:
        if ($debug)   echo "  $message\n";
        break;
    }
  }
?>