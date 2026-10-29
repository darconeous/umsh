#!/bin/sh
# Export the iOS app's strings for translation: one .xcloc per language,
# each holding an XLIFF with every string, its translator comment, and any
# translation already in the string catalogs.
#
#   scripts/ios/export-localizations.sh [output-dir] [language...]
#
# The default output is target/ios-localizations, in English only, which is
# the check CI runs: extraction failing is how a broken catalog shows up.
# Send the .xcloc files to translators; bring them back with
#   xcodebuild -importLocalizations -project apps/ios/UMSH.xcodeproj \
#       -localizationPath <file>.xcloc
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
output=${1:-"$repo_root/target/ios-localizations"}
[ "$#" -gt 0 ] && shift
[ "$#" -eq 0 ] && set -- en

languages=""
for language in "$@"; do
    languages="$languages -exportLanguage $language"
done

# shellcheck disable=SC2086 # one -exportLanguage per word, by design
xcodebuild -exportLocalizations \
    -project "$repo_root/apps/ios/UMSH.xcodeproj" \
    -localizationPath "$output" \
    -sdk iphoneos \
    $languages

echo "Exported to $output"
