# Malicious NPM Module Checker

## Purpose
This shell script scans a specified directory for `package.json` or `package-lock.json` files within `node_modules` directories to identify potentially malicious or compromised npm modules. It checks for known malicious versions of specific npm packages, including those affected by hijacking, protestware, malware, or severe vulnerabilities.

## Usage
Run the script by providing a directory path to scan:

```bash
./malicious_npm_module_check.sh <directory_path>
```

- **`<directory_path>`**: The directory to recursively search for `package.json` or `package-lock.json` files.
- If no directory is provided or the directory does not exist, the script will display an error message and exit.
- The script outputs the paths of any matching malicious modules and their versions, or a message indicating no matches were found.

## Dependencies
- **jq**: A lightweight command-line JSON processor used to parse `package.json` files. The script checks for `jq` and exits with an error if it is not installed.

### Installing `jq`
- On Debian/Ubuntu:
  ```bash
  sudo apt-get install jq
  ```
- On macOS (using Homebrew):
  ```bash
  brew install jq
  ```
- On CentOS/RHEL:
  ```bash
  sudo yum install jq
  ```

## Example
```bash
./malicious_npm_module_check.sh /path/to/project
```

Output:
```
Searching for compromised npm modules in '/path/to/project'...
--------------------------------------------------
Found 'chalk' at version 5.6.1 at /path/to/project/node_modules/chalk
--------------------------------------------------
```

Or, if no malicious modules are found:
```
Searching for compromised npm modules in '/path/to/project'...
--------------------------------------------------
No modules with version equal to the malicious version(s) found.
--------------------------------------------------
```

## Notes
- The script uses a predefined JSON-like structure listing known malicious npm modules and their affected versions.
- It recursively searches for `package.json` and `package-lock.json` files within `node_modules` directories.
- Only modules with exact version matches to the malicious versions are reported.