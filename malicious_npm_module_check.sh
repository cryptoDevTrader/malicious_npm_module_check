#!/bin/sh

# Check if a directory path was provided
if [ -z "$1" ]; then
    echo "Usage: ./malicious_npm_module_check.sh <directory_path>"
    exit 1
fi

START_DIR="$1"

if [ ! -d "$START_DIR" ]; then
    echo "Error: Directory not found at '$START_DIR'"
    exit 1
fi

# --- Check for 'jq' dependency ---
if ! command -v jq >/dev/null 2>&1
then
    echo "Error: 'jq' is not installed."
    echo "This script requires 'jq' to parse JSON. Please install it to continue."
    exit 1
fi

echo "Searching for compromised npm modules in '$START_DIR'..."
echo "--------------------------------------------------"

# Define malicious modules and their versions as a JSON-like structure
# This list includes modules affected by hijacking, protestware, malware, and severe vulnerabilities.
MODULES='{
    "@babel/traverse": ["7.23.6"],
    "@coveops/abi": ["2.0.1"],
    "@ctrl/deluge": ["7.2.2"],
    "@ctrl/golang-template": ["1.4.3"],
    "@ctrl/magnet-link": ["4.0.4"],
    "@ctrl/ngx-codemirror": ["7.0.2"],
    "@ctrl/ngx-csv": ["6.0.2"],
    "@ctrl/ngx-emoji-mart": ["9.2.2"],
    "@ctrl/ngx-rightclick": ["4.0.2"],
    "@ctrl/qbittorrent": ["9.7.2"],
    "@ctrl/react-adsense": ["2.0.2"],
    "@ctrl/shared-torrent": ["6.3.2"],
    "@ctrl/tinycolor": ["4.1.1", "4.1.2"],
    "@ctrl/torrent-file": ["4.1.2"],
    "@ctrl/transmission": ["7.3.1"],
    "@ctrl/ts-base32": ["4.0.2"],
    "@duckdb/duckdb-wasm": ["1.29.2"],
    "@duckdb/node-api": ["1.3.3"],
    "@duckdb/node-bindings": ["1.3.3"],
    "@nativescript-community/gesturehandler": ["2.0.35"],
    "@nativescript-community/sentry": ["4.6.43"],
    "@nativescript-community/text": ["1.6.13"],
    "@nativescript-community/ui-collectionview": ["6.0.6"],
    "@nativescript-community/ui-drawer": ["0.1.30"],
    "@nativescript-community/ui-image": ["4.5.6"],
    "@nativescript-community/ui-material-bottomsheet": ["7.2.72"],
    "@nativescript-community/ui-material-core": ["7.2.76"],
    "@nativescript-community/ui-material-core-tabs": ["7.2.76"],
    "@nx/devkit": ["20.9.0", "21.5.0"],
    "@nx/enterprise-cloud": ["3.2.0"],
    "@nx/eslint": ["21.5.0"],
    "@nx/js": ["20.9.0", "21.5.0"],
    "@nx/key": ["3.2.0"],
    "@nx/node": ["20.9.0", "21.5.0"],
    "@nx/workspace": ["20.9.0", "21.5.0"],
    "@pkgr/core": ["0.2.8"],
    "angulartics2": ["14.1.2"],
    "ansi-regex": ["6.2.1"],
    "ansi-styles": ["6.2.2"],
    "backslash": ["0.2.1"],
    "chalk": ["5.6.1"],
    "chalk-template": ["1.1.1"],
    "coa": ["2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.2", "3.1.3"],
    "color-convert": ["3.1.1"],
    "color-name": ["2.0.1"],
    "color-string": ["2.1.1"],
    "colors": ["1.4.1", "1.4.44"],
    "cross-env": ["5.1.5", "5.1.6"],
    "debug": ["4.4.2"],
    "duckdb": ["1.3.3"],
    "encounter-playground": ["0.0.5"],
    "error-ex": ["1.3.3"],
    "eslint-config-prettier": ["8.10.1", "9.1.1", "10.1.6", "10.1.7"],
    "eslint-plugin-prettier": ["4.2.2", "4.2.3"],
    "eslint-scope": ["3.7.2"],
    "event-stream": ["3.3.6"],
    "faker": ["6.6.6"],
    "flatmap-stream": ["0.1.1"],
    "got-fetch": ["5.1.11", "5.1.12"],
    "has-ansi": ["6.0.1"],
    "is": ["3.3.1", "5.0.0"],
    "is-arrayish": ["0.3.3"],
    "json-rules-engine-simplified": ["0.2.4", "0.2.1"],
    "koa2-swagger-ui": ["5.11.2", "5.11.1"],
    "napi-postinstall": ["0.3.1"],
    "ngx-color": ["10.0.2"],
    "ngx-toastr": ["19.0.2"],
    "ngx-trend": ["8.0.1"],
    "node-ipc": ["9.2.2", "11.0.0"],
    "nx": ["20.9.0", "20.10.0", "20.11.0", "20.12.0", "21.5.0", "21.6.0", "21.7.0", "21.8.0"],
    "pac-resolver": ["5.0.0"],
    "prebid": ["10.9.1", "10.9.2"],
    "rand-user-agent": ["1.0.110", "2.0.83", "2.0.84"],
    "rc": ["1.2.9"],
    "react-complaint-image": ["0.0.35"],
    "react-jsonschema-form-conditionals": ["0.3.21"],
    "react-jsonschema-form-extras": ["1.0.4"],
    "rxnt-authentication": ["0.0.6"],
    "rxnt-healthchecks-nestjs": ["1.0.5"],
    "rxnt-kue": ["1.0.7"],
    "simple-swizzle": ["0.2.3"],
    "slice-ansi": ["7.1.1"],
    "strip-ansi": ["7.1.1"],
    "supports-color": ["10.2.1"],
    "supports-hyperlinks": ["4.1.1"],
    "swc-plugin-component-annotate": ["1.9.2"],
    "synckit": ["0.11.9"],
    "ts-gaussian": ["3.0.6"],
    "ua-parser-js": ["0.7.29", "0.8.0", "1.0.0"],
    "wrap-ansi": ["9.0.1"]
}'

# Initialize a flag to track if any matching modules are found
found_match=0

# Find all package.json files recursively
find "$START_DIR" -type f \( -path '*/node_modules/*/package.json' -o -path '*/node_modules/package-lock.json' \) | while read -r file; do
    # Extract the module name and version using jq
    module_name=$(jq -r '.name // empty' "$file")
    installed_version=$(jq -r '.version // empty' "$file")

    # Check if the module is in the malicious list
    if [ -n "$module_name" ] && [ -n "$installed_version" ]; then
        # Get the malicious versions for the module
        malicious_versions=$(echo "$MODULES" | jq -r --arg mod "$module_name" '.[$mod] // [] | .[]')
        
        # Check if the installed version is in the malicious versions
        for version in $malicious_versions; do
            if [ "$installed_version" = "$version" ]; then
                module_path=$(dirname "$file")
                echo "Found '$module_name' at version $installed_version at $module_path"
                found_match=1
            fi
        done
    fi
done

# Check if any matching modules were found
if [ "$found_match" -eq 0 ]; then
    echo "No modules with version equal to the malicious version(s) found."
fi

echo "--------------------------------------------------"