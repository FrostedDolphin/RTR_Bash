#!/bin/bash

# Copyright 2025 Google LLC
# ...license text...

if [ "$(uname -s)" = "Linux" ]; then
    FIND_OPTS="-P"
    REGEX_EXPR="-regextype posix-extended"
else
    FIND_OPTS="-PE"
    REGEX_EXPR=""
fi

DEFAULT_TARGETS=( \
    /tmp \
    /var/tmp \
    /var/www \
    /srv/www \
)

targets=()
if [ -n "${SCAN_TARGETS:-}" ]; then
    targets=($SCAN_TARGETS)
fi

if [ "$#" -gt 0 ]; then
    targets=("$@")
else
    if [ "${#targets[@]}" -eq 0 ]; then
        targets=("${DEFAULT_TARGETS[@]}")
    fi
fi

existing_targets=()
for t in "${targets[@]}"; do
    if [ -e "$t" ]; then
        existing_targets+=("$t")
    else
        echo "Warning: target '$t' does not exist; skipping." >&2
    fi
done

if [ "${#existing_targets[@]}" -eq 0 ]; then
    echo "No valid files or directories to scan. Provide paths as arguments or set SCAN_TARGETS." >&2
    exit 1
fi

hex_pattern="488b05........48890424e8........48b8................48890424(..){0,5}e8........eb.."
long_num="115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951"

PREFILTER_STR_MIN=6
PREFILTER_MIN_MATCHES=2
long_num_prefix="${long_num:0:12}"
PREFILTER_KEYWORDS_REGEX="regex|mime|decompress|mimeheader|resolvereference"

build_wide_pattern() {
    echo -n "$1" | sed 's/./&\\x00/g'
}

prefilter_file() {
    local file="$1"
    if ! command -v strings >/dev/null 2>&1; then
        return 0
    fi
    local sample
    sample=$(head -c 65536 "$file" 2>/dev/null | strings -a -n "$PREFILTER_STR_MIN" 2>/dev/null | tr '\n' ' ' | tr 'A-Z' 'a-z')
    local keyword_hits=0
    if printf '%s' "$sample" | grep -oE "$PREFILTER_KEYWORDS_REGEX" >/dev/null 2>&1; then
        local uniq_kw_count
        uniq_kw_count=$(printf '%s' "$sample" | grep -oE "$PREFILTER_KEYWORDS_REGEX" | sort -u | wc -l)
        keyword_hits=$((keyword_hits + uniq_kw_count))
    fi
    if printf '%s' "$sample" | grep -qF "$long_num_prefix"; then
        keyword_hits=$((keyword_hits + 1))
    fi
    if [ "$keyword_hits" -ge "$PREFILTER_MIN_MATCHES" ]; then
        return 0
    fi
    return 1
}

count_files_with_progress() {
    local target="$1"
    local total_count=0
    if [ -d "$target" ]; then
        local second_level_dirs
        second_level_dirs=$(find $FIND_OPTS "$target" -maxdepth 2 -mindepth 2 -type d \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null)
        local second_level_count
        second_level_count=$(printf '%s\n' "$second_level_dirs" | wc -l)
        local subdirs=""
        local total_dirs=0
        if [ "$second_level_count" -gt 0 ]; then
            subdirs="$second_level_dirs"
            total_dirs=$second_level_count
        else
            subdirs=$(find $FIND_OPTS "$target" -maxdepth 1 -type d \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null | tail -n +2)
            total_dirs=$(printf '%s\n' "$subdirs" | wc -l)
        fi
        local root_count
        root_count=$(find $FIND_OPTS "$target" -maxdepth 2 $REGEX_EXPR -type f -size -10M \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null | wc -l)
        total_count=$root_count
        if [ "$total_dirs" -ne 0 ]; then
            for dir in $subdirs; do
                local count
                count=$(find $FIND_OPTS "$dir" $REGEX_EXPR -type f -size -10M \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null | wc -l)
                total_count=$((total_count + count))
            done
        fi
    elif [ -f "$target" ]; then
        total_count=1
    fi
    echo "$total_count"
}

check_file() {
    local file="$1"
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        return
    fi
    file_header=$(head -c 2 "$file" 2>/dev/null | xxd -p)
    if [ "$file_header" != "7f45" ]; then
        return
    fi
    if ! prefilter_file "$file"; then
        return
    fi
    str2="regex"
    str2_wide=$(build_wide_pattern "$str2")
    if ! grep -iaPq "$str2|$str2_wide" "$file"; then return; fi
    str3="mime"
    str3_wide=$(build_wide_pattern "$str3")
    if ! grep -iaPq "$str3|$str3_wide" "$file"; then return; fi
    str4="decompress"
    str4_wide=$(build_wide_pattern "$str4")
    if ! grep -iaPq "$str4|$str4_wide" "$file"; then return; fi
    str5="MIMEHeader"
    str5_wide=$(build_wide_pattern "$str5")
    if ! grep -iaPq "$str5|$str5_wide" "$file"; then return; fi
    str6="ResolveReference"
    str6_wide=$(build_wide_pattern "$str6")
    if ! grep -iaPq "$str6|$str6_wide" "$file"; then return; fi
    str7_wide=$(build_wide_pattern "$long_num")
    if ! grep -iaPq "$long_num|$str7_wide" "$file"; then return; fi
    if ! xxd -p "$file" | tr -d '\n' | grep -Pq "$hex_pattern"; then
        return
    fi
    echo "MATCH: $file"
    echo "Found evidence of potential BRICKSTORM compromise."
    echo "You should consider performing a forensic investigation of the system."
    echo
}

export -f check_file
export -f build_wide_pattern
export -f count_files_with_progress
export -f prefilter_file
export long_num
export hex_pattern

start_time=$(date +%s)
start_timestamp=$(date)

total_files=0
echo "Scan started at: $start_timestamp"
echo "Counting files to scan..."

for target in "${existing_targets[@]}"; do
    if [ -d "$target" ] || [ -f "$target" ]; then
        count=$(count_files_with_progress "$target")
        total_files=$((total_files + count))
    fi
done

if [ "$total_files" -eq 0 ]; then
    echo "No files to scan."
    exit 0
fi

echo "Found $total_files files to scan."
echo

for target in "${existing_targets[@]}"; do
    if [ -d "$target" ]; then
        find $FIND_OPTS "$target" $REGEX_EXPR -type f -size -10M \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) -exec bash -c 'check_file "$0"' {} \; 2>/dev/null
    elif [ -f "$target" ]; then
        check_file "$target"
    else
        echo "Warning: '$target' is not a valid file or directory. Skipping." >&2
    fi
done

end_time=$(date +%s)
end_timestamp=$(date)
duration=$((end_time - start_time))

if [ $duration -lt 60 ]; then
    duration_str="${duration}s"
elif [ $duration -lt 3600 ]; then
    minutes=$((duration / 60))
    seconds=$((duration % 60))
    duration_str="${minutes}m ${seconds}s"
else
    hours=$((duration / 3600))
    minutes=$(((duration % 3600) / 60))
    seconds=$((duration % 60))
    duration_str="${hours}h ${minutes}m ${seconds}s"
fi

echo
echo "Scan completed at: $end_timestamp"
echo "Total scan time: $duration_str"
