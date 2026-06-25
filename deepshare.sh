#!/bin/bash

# DeepShare — SMB share permission checker
# by JazzTheRabbit

# ── Colors ────────────────────────────────────────────────────────────────────
R='\033[1;31m'
G='\033[1;32m'
Y='\033[1;33m'
C='\033[0;36m'
NC='\033[1;34m'
M='\033[1;35m'
W='\033[1;37m'
D='\033[2m'
B='\033[1m'
O='\033[38;5;208m'
F='\033[1;93m'      
N='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGETS=()
SHARES=()
AUTO_ENUM=false
EXT_FILTER=()
DRY_RUN=false
SPOOF_NAME=""
USER=""
PASS=""
DOMAIN=""
HASH=""
NULL=false
KERBEROS=false
MAX_DEPTH=5
SLEEP=0
TIMEOUT=10
OUT_FORMAT="normal"
OUT_FILE=""
EXT_ALL=false
LIST_ONLY=false

# ── Result storage ─────────────────────────────────────────────────────────────
declare -a JSON_ROWS=()
declare -a CSV_ROWS=()
declare -a FILE_HITS=()

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    echo -e ""
    echo -e "Usage: $(basename "$0") -t <target> [OPTIONS]"
    echo -e "       $(basename "$0") --help"
    echo -e ""
    echo -e "Target:"
    echo -e "  -t  --target    <IP|hostname|UNC|file>     Target host, UNC path, or file with hosts"
    echo -e "  -s  --share     <share[/subpath]>          Share name(s), comma-separated"
    echo -e "                                             Optionally specify a subpath to start from"
    echo -e "                                             e.g. Users/Public starts scan inside Public"
    echo -e "  -A  --auto                                 Auto-enumerate all accessible Disk shares"
    echo -e "                                             Uses smbclient -L at the raw SMB protocol level"
    echo -e "                                             bypassing Windows API restrictions (NetShareEnum)"
    echo -e ""
    echo -e "Authentication:"
    echo -e "  -u  --user      <username>"
    echo -e "  -p  --pass      <password>                 Use -P/--prompt to avoid plaintext in history"
    echo -e "  -P  --prompt                               Prompt for password interactively"
    echo -e "  -H  --hash      <hash>                     NTLM pass-the-hash  Format: :NT  or  LM:NT"
    echo -e "  -d  --domain    <domain>"
    echo -e "  -n  --null                                 Null session (anonymous)"
    echo -e "                                             Passing -u '' -p '' also triggers null session"
    echo -e "  -k  --kerberos                             Kerberos auth via current ccache"
    echo -e "                                             Requires KRB5CCNAME exported and FQDN as target"
    echo -e ""
    echo -e "Scan:"
    echo -e "  -D  --depth     <depth>                    Max recursion depth            [Default: 5, Max: 10]"
    echo -e "  -S  --sleep     <seconds>                  Base sleep between requests    [Default: 0]"
    echo -e "                                             Jitter of 0-2s is added automatically when set"
    echo -e "  -T  --timeout   <seconds>                  smbclient connection timeout   [Default: 10]"
    echo -e "  -e  --ext       <ext[,ext,...]|all>        Flag files matching extension during traversal"
    echo -e "                                             all: kdbx kdb psafe3 pfx p12 pem key ppk"
    echo -e "                                                  pdf docx doc xlsx xls pptx ppt"
    echo -e "                                                  config conf cfg ini env xml yaml yml"
    echo -e "                                                  ps1 bat cmd sh vbs sql db sqlite bak"
    echo -e "  -z  --no-write                             Skip all write tests — read-only mode"
    echo -e "                                             Combined with -L: shows root permissions without"
    echo -e "                                             any write attempts"
    echo -e "  -L  --list                                 Test and list root-level permissions per share"
    echo -e "                                             No recursion into subfolders"
    echo -e "                                             Combined with --no-write: read-only root check"
    echo -e "  -N  --spoof     <name>                     Spoof NetBIOS workstation name [Default: DESKTOP-XXXXXXXX]"
    echo -e "                                             Blends traffic as a normal Windows workstation"
    echo -e ""
    echo -e "Output:"
    echo -e "  -f  --format    <normal|json|csv>          Output format                  [Default: normal]"
    echo -e "  -o  --output    <file>                     Write output to file"
    echo -e ""
    echo -e "Help:"
    echo -e "  -h  --help                                 Show this menu"
    echo -e ""
    exit 0
}

# ── Target parser — handles UNC, SPN, file, and single host ───────────────────
parse_target() {
    local raw="$1"

    if [[ -f "$raw" ]]; then
        while IFS= read -r line; do
            line="${line// /}"
            [[ -z "$line" || "$line" == \#* ]] && continue
            TARGETS+=("$line")
        done < "$raw"
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            echo -e "${R}[!] File '${raw}' is empty or has no valid hosts.${N}"
            exit 1
        fi
        return
    fi

    local norm
    norm=$(echo "$raw" | tr '\\' '/' | sed 's|^/*||')

    if [[ "$KERBEROS" == true ]]; then
        if [[ "$norm" =~ ^cifs/(.+)$ ]]; then
            TARGETS+=("${BASH_REMATCH[1]}")
        else
            TARGETS+=("$norm")
        fi
        return
    fi

    if [[ "$norm" == */* ]]; then
        TARGETS+=("${norm%%/*}")
        local share_part="${norm#*/}"
        if [[ ${#SHARES[@]} -eq 0 && -n "$share_part" ]]; then
            IFS='/' read -ra SHARES <<< "$share_part"
        fi
    else
        TARGETS+=("$norm")
    fi
}

# ── Long option translator ────────────────────────────────────────────────────
translate_args() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --target)    args+=("-t" "$2"); shift 2 ;;
            --share)     args+=("-s" "$2"); shift 2 ;;
            --auto)      args+=("-A");      shift   ;;
            --user)      args+=("-u" "$2"); shift 2 ;;
            --pass)      args+=("-p" "$2"); shift 2 ;;
            --prompt)    args+=("-P");      shift   ;;
            --hash)      args+=("-H" "$2"); shift 2 ;;
            --domain)    args+=("-d" "$2"); shift 2 ;;
            --null)      args+=("-n");      shift   ;;
            --kerberos)  args+=("-k");      shift   ;;
            --depth)     args+=("-D" "$2"); shift 2 ;;
            --sleep)     args+=("-S" "$2"); shift 2 ;;
            --timeout)   args+=("-T" "$2"); shift 2 ;;
            --ext)       args+=("-e" "$2"); shift 2 ;;
            --no-write)  args+=("-z");      shift   ;;
            --list)      args+=("-L");      shift   ;;
            --spoof)     args+=("-N" "$2"); shift 2 ;;
            --format)    args+=("-f" "$2"); shift 2 ;;
            --output)    args+=("-o" "$2"); shift 2 ;;
            --help)      args+=("-h");      shift   ;;
            *)           args+=("$1");      shift   ;;
        esac
    done
    printf "%s\0" "${args[@]}"
}

# ── Argument parser ───────────────────────────────────────────────────────────
parse_args() {
    local raw_target=""

    local translated=()
    while IFS= read -r -d $'\0' arg; do
        translated+=("$arg")
    done < <(translate_args "$@")
    set -- "${translated[@]}"

    while getopts "t:s:u:p:PH:d:D:S:T:e:f:o:N:nkAzLh" opt; do
        case $opt in
            t) raw_target="$OPTARG" ;;
            s) IFS=',' read -ra SHARES <<< "$OPTARG" ;;
            u) USER="$OPTARG" ;;
            p) PASS="$OPTARG" ;;
            P) read -rsp "[*] Password: " PASS; echo ;;
            H) HASH="$OPTARG" ;;
            d) DOMAIN="$OPTARG" ;;
            D) MAX_DEPTH="$OPTARG" ;;
            S) SLEEP="$OPTARG" ;;
            T) TIMEOUT="$OPTARG" ;;
            e) if [[ "${OPTARG,,}" == "all" ]]; then
                    EXT_FILTER=(kdbx kdb psafe3 pfx p12 pem key ppk pdf docx doc xlsx xls
                                pptx ppt config conf cfg ini env xml yaml yml ps1 bat cmd
                                sh vbs sql db sqlite mdb accdb bak)
                    EXT_ALL=true
               else
                    IFS=',' read -ra EXT_FILTER <<< "${OPTARG,,}"
                    EXT_ALL=false
LIST_ONLY=false
               fi ;;
            f) OUT_FORMAT="$OPTARG" ;;
            o) OUT_FILE="$OPTARG" ;;
            N) SPOOF_NAME="$OPTARG" ;;
            n) NULL=true ;;
            k) KERBEROS=true ;;
            A) AUTO_ENUM=true ;;
            z) DRY_RUN=true ;;
            L) LIST_ONLY=true ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    [[ -z "$raw_target" ]] && usage
    parse_target "$raw_target"

    if [[ "$AUTO_ENUM" == false && ${#SHARES[@]} -eq 0 ]]; then
        usage
    fi

    if [[ "$MAX_DEPTH" -gt 10 ]]; then
        echo -e "${Y}[!] --depth capped at 10 (requested: ${MAX_DEPTH})${N}"
        MAX_DEPTH=10
    fi

    if [[ -n "$HASH" && -z "$USER" ]]; then
        echo -e "${Y}[!] --hash used without --user — defaulting to 'Administrator'${N}"
        USER="Administrator"
    fi

    USER="${USER// /}"
    PASS="${PASS// /}"
    if [[ -z "$USER" && -z "$PASS" && -z "$HASH" && "$KERBEROS" == false ]]; then
        NULL=true
    fi

    if [[ "$KERBEROS" == true ]]; then
        for t in "${TARGETS[@]}"; do
            if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo -e "${Y}[!] Kerberos requires a hostname not an IP — '${t}' may fail.${N}"
                echo -e "    ${D}Use the FQDN e.g. dc01.corp.local and ensure KRB5CCNAME is exported.${N}"
            fi
        done
    fi

    if [[ -z "$SPOOF_NAME" ]]; then
        local rand
        rand=$(tr -dc 'A-F0-9' < /dev/urandom | head -c8)
        SPOOF_NAME="DESKTOP-${rand}"
    fi

    case "$OUT_FORMAT" in
        normal|json|csv) ;;
        *) echo -e "${R}[!] Invalid format '${OUT_FORMAT}'. Use: normal, json, csv${N}"; exit 1 ;;
    esac
}

# ── Build smbclient auth arguments ────────────────────────────────────────────
smb_auth() {
    SMB_AUTH=("--timeout=${TIMEOUT}" "--netbiosname=${SPOOF_NAME}")

    if [[ "$KERBEROS" == true ]]; then
        SMB_AUTH+=(-k)
        [[ -n "$USER" ]]   && SMB_AUTH+=(-U "${DOMAIN:+${DOMAIN}\\}${USER}")
        [[ -n "$DOMAIN" ]] && SMB_AUTH+=(-W "$DOMAIN")

    elif [[ "$NULL" == true ]]; then
        SMB_AUTH+=(-N)

    elif [[ -n "$HASH" ]]; then
        local nt="${HASH##*:}"
        SMB_AUTH+=(-U "${DOMAIN:+${DOMAIN}\\}${USER}" --pw-nt-hash "$nt")
        [[ -n "$DOMAIN" ]] && SMB_AUTH+=(-W "$DOMAIN")

    elif [[ -n "$USER" && -z "$PASS" ]]; then
        SMB_AUTH+=(-U "${DOMAIN:+${DOMAIN}\\}${USER}" --password='')
        [[ -n "$DOMAIN" ]] && SMB_AUTH+=(-W "$DOMAIN")

    else
        SMB_AUTH+=(-U "${DOMAIN:+${DOMAIN}\\}${USER}" --password="${PASS}")
        [[ -n "$DOMAIN" ]] && SMB_AUTH+=(-W "$DOMAIN")
    fi
}

# ── Jitter-aware sleep ────────────────────────────────────────────────────────
do_sleep() {
    local should_sleep
    should_sleep=$(awk -v s="$SLEEP" 'BEGIN { print (s > 0) ? "yes" : "no" }')
    [[ "$should_sleep" == "no" ]] && return
    local jitter=$(( RANDOM % 3 ))
    sleep "$(awk -v s="$SLEEP" -v j="$jitter" 'BEGIN { print s + j }')"
}

# ── Enumerate accessible Disk shares via smbclient -L ─────────────────────────
enum_shares() {
    local raw
    raw=$(smbclient -L "//${TARGET}" "${SMB_AUTH[@]}" 2>&1)

    mapfile -t SHARES < <(
        echo "$raw" | awk '
            /Disk/ {
                line = $0
                gsub(/^[ \t]+/, "", line)
                if (match(line, /[[:space:]]+Disk[[:space:]]/)) {
                    name = substr(line, 1, RSTART - 1)
                    sub(/[[:space:]]+$/, "", name)
                    print name
                }
            }
        '
    )

    if [[ ${#SHARES[@]} -eq 0 ]]; then
        printf "${B}SMB${N}  ${C}%-15s${N}  ${D}445${N}  ${NC}[NO SHARES]${N}\n" "$TARGET"
        return 1
    fi
}

# ── Execute smbclient command — retries once on transient network errors ───────
smb_run() {
    local share="$1" rpath="$2" cmd="$3"
    local full_cmd out

    if [[ -z "$rpath" || "$rpath" == "/" ]]; then
        full_cmd="$cmd"
    else
        full_cmd="cd \"${rpath}\"; ${cmd}"
    fi

    out=$(smbclient "//${TARGET}/${share}" "${SMB_AUTH[@]}" -c "$full_cmd" 2>&1)

    if echo "$out" | grep -qiE "NT_STATUS_IO_TIMEOUT|NT_STATUS_CONNECTION_DISCONNECTED|NT_STATUS_CONNECTION_RESET"; then
        sleep 1
        out=$(smbclient "//${TARGET}/${share}" "${SMB_AUTH[@]}" -c "$full_cmd" 2>&1)
    fi

    echo "$out"
}

# ── Test READ access ──────────────────────────────────────────────────────────
test_read() {
    local share="$1" path="$2"
    local out
    out=$(smb_run "$share" "$path" "ls")

    if echo "$out" | grep -qiE "NT_STATUS_ACCESS_DENIED"; then
        echo "NOPRIVILEGE"
    elif echo "$out" | grep -qiE "NT_STATUS_BAD_NETWORK_NAME|NT_STATUS_OBJECT_NAME_NOT_FOUND"; then
        echo "NOTFOUND"
    elif echo "$out" | grep -qiE "NT_STATUS_"; then
        echo "DENIED"
    else
        echo "ALLOWED"
    fi
}

# ── Test WRITE access ─────────────────────────────────────────────────────────
test_write() {
    if [[ "$DRY_RUN" == true ]]; then
        echo "SKIPPED SKIPPED"
        return
    fi

    local share="$1" path="$2"
    local rand
    rand=$(tr -dc 'a-f0-9' < /dev/urandom | head -c8)

    local fname="${rand}.dat"
    local local_tmp="/tmp/${fname}"

    printf '' > "$local_tmp"
    trap "rm -f '${local_tmp}'" RETURN

    local up_out
    up_out=$(smb_run "$share" "$path" "put ${local_tmp} ${fname}")

    if echo "$up_out" | grep -qiE "NT_STATUS_ACCESS_DENIED|NT_STATUS_MEDIA_WRITE_PROTECTED|NT_STATUS_OBJECT_PATH_NOT_FOUND"; then
        echo "DENIED DENIED"
        return
    fi

    local verify
    verify=$(smb_run "$share" "$path" "ls ${fname}")

    if echo "$verify" | grep -q "$fname"; then
        local del_out
        del_out=$(smb_run "$share" "$path" "del ${fname}" 2>&1)
        if echo "$del_out" | grep -qiE "NT_STATUS_"; then
            echo "ALLOWED NODELETE"
        else
            echo "ALLOWED DELETE"
        fi
    else
        echo "DENIED DENIED"
    fi
}

# ── Flag interesting files by extension during traversal ─────────────────────
scan_files() {
    local share="$1" path="$2"
    [[ ${#EXT_FILTER[@]} -eq 0 ]] && return

    local listing
    listing=$(smb_run "$share" "$path" "ls")

    local ext_regex
    ext_regex=$(IFS='|'; echo "${EXT_FILTER[*]}")

    while IFS= read -r line; do
        echo "$line" | grep -qiE "^\s+\."                  && continue
        echo "$line" | grep -qiE "[[:space:]]+D[[:space:]]" && continue

        local fname
        fname=$(echo "$line" | awk '{
            line = $0; gsub(/^[ \t]+/, "", line)
            if (match(line, /  +[AaHhRrSs]*  /)) {
                name = substr(line, 1, RSTART - 1)
                sub(/[ \t]+$/, "", name)
                print name
            }
        }')

        [[ -z "$fname" ]] && continue

        local ext="${fname##*.}"
        ext="${ext,,}"

        if echo "$ext" | grep -qiE "^(${ext_regex})$"; then
            local full_path="${path:+${path}/}${fname}"
            FILE_HITS+=("//${TARGET}/${share}/${full_path}")
            local ext_upper="${ext^^}"
            printf "${B}SMB${N}  ${C}%-15s${N}  ${D}445${N}  ${W}%-18s${N}  ${F}[${ext_upper} File Found]${N}  ${B}%s${N}\n" \
                "$TARGET" "$share" "$full_path"
            if [[ "$OUT_FORMAT" == "json" ]]; then
                JSON_ROWS+=("{\"type\":\"file\",\"target\":\"${TARGET}\",\"port\":445,\"share\":\"${share}\",\"path\":\"${full_path}\",\"extension\":\"${ext}\"}")
            fi
            if [[ "$OUT_FORMAT" == "csv" ]]; then
                CSV_ROWS+=("${TARGET},445,${share},\"${full_path}\",FILE,${ext}")
            fi
        fi
    done <<< "$listing"
}

# ── List subdirectories — column-offset awk handles filenames with spaces ──────
list_subdirs() {
    local share="$1" path="$2"
    smb_run "$share" "$path" "ls" | awk '
        /^  / {
            line = substr($0, 3)
            if (match(line, /  +[DdAaHhRrSs]+  /)) {
                name = substr(line, 1, RSTART - 1)
                attrs = substr(line, RSTART, RLENGTH)
                sub(/ +$/, "", name)
                if (attrs ~ /[Dd]/ && name != "." && name != "..") {
                    print name
                }
            }
        }
    '
}

# ── Print result line ─────────────────────────────────────────────────────────
print_line() {
    local share="$1" path="$2" rr="$3" wr="$4" dr="$5"
    local display tag tag_plain port="445"

    display="${path:-\\}"

    if [[ "$DRY_RUN" == true ]]; then
        if [[ "$rr" == "ALLOWED" ]]; then
            tag="${W}[${G}READ${W}]${N}"
            tag_plain="READ"
        else
            tag="${W}[${NC}NO ACCESS${W}]${N}"
            tag_plain="NO ACCESS"
        fi
    elif [[ "$rr" == "ALLOWED" && "$wr" == "ALLOWED" && "$dr" == "DELETE" ]]; then
        tag="${W}[${G}READ${W}][${R}WRITE${W}][${O}DELETE${W}]${N}"
        tag_plain="READ+WRITE+DELETE"
    elif [[ "$rr" == "ALLOWED" && "$wr" == "ALLOWED" ]]; then
        tag="${W}[${G}READ${W}][${R}WRITE${W}]${N}"
        tag_plain="READ+WRITE"
    elif [[ "$rr" == "ALLOWED" ]]; then
        tag="${W}[${G}READ${W}]${N}"
        tag_plain="READ"
    elif [[ "$rr" == "DENIED" && "$wr" == "ALLOWED" && "$dr" == "DELETE" ]]; then
        tag="${W}[${R}WRITE${W}][${O}DELETE${W}]${N}"
        tag_plain="WRITE+DELETE"
    elif [[ "$rr" == "DENIED" && "$wr" == "ALLOWED" ]]; then
        tag="${W}[${R}WRITE${W}]${N}"
        tag_plain="WRITE"
    elif [[ "$rr" == "NOPRIVILEGE" ]]; then
        tag="${W}[${NC}INSUFFICIENT PRIVILEGES${W}]${N}"
        tag_plain="INSUFFICIENT PRIVILEGES"
    elif [[ "$rr" == "NOTFOUND" ]]; then
        tag="${W}[${R}SHARE NOT FOUND${W}]${N}"
        tag_plain="SHARE NOT FOUND"
    else
        tag="${W}[${NC}NO ACCESS${W}]${N}"
        tag_plain="NO ACCESS"
    fi

    printf "${B}SMB${N}  ${C}%-15s${N}  ${D}%s${N}  ${W}%-18s${N}  %b  ${B}%s${N}\n" \
        "$TARGET" "$port" "$share" "$tag" "$display"

    if [[ "$OUT_FORMAT" == "json" ]]; then
        local json_path="${path:-/}"
        local json_read json_write json_delete
        json_read=$([ "$rr" == "ALLOWED" ] && echo true || echo false)
        json_write=$([ "$wr" == "ALLOWED" ] && echo true || echo false)
        json_delete=$([ "$dr" == "DELETE" ] && echo true || echo false)
        JSON_ROWS+=("{\"type\":\"share\",\"target\":\"${TARGET}\",\"port\":${port},\"share\":\"${share}\",\"path\":\"${json_path}\",\"read\":${json_read},\"write\":${json_write},\"delete\":${json_delete},\"access\":\"${tag_plain}\"}")
    fi

    if [[ "$OUT_FORMAT" == "csv" ]]; then
        CSV_ROWS+=("${TARGET},${port},${share},\"${path:-/}\",${rr},${wr},${dr},${tag_plain}")
    fi

    if [[ "$OUT_FORMAT" == "normal" && -n "$OUT_FILE" ]]; then
        printf "SMB  %-15s  %s  %-18s  %-12s  %s\n" \
            "$TARGET" "$port" "$share" "$tag_plain" "$display" >> "$OUT_FILE"
    fi
}

# ── Recursive directory scan ───────────────────────────────────────────────────
deep_scan() {
    local share="$1" current="$2" depth="$3"
    [[ $depth -gt $MAX_DEPTH ]] && return

    scan_files "$share" "$current"

    local dirs
    mapfile -t dirs < <(list_subdirs "$share" "$current")

    for dir in "${dirs[@]}"; do
        [[ -z "$dir" ]] && continue

        local sub
        if [[ -z "$current" ]]; then
            sub="$dir"
        else
            sub="${current}/${dir}"
        fi

        local rr wr dr write_result
        rr=$(test_read "$share" "$sub")
        write_result=$(test_write "$share" "$sub")
        wr=$(echo "$write_result" | awk '{print $1}')
        dr=$(echo "$write_result" | awk '{print $2}')
        print_line "$share" "$sub" "$rr" "$wr" "$dr"

        do_sleep

        [[ "$rr" == "ALLOWED" ]] && deep_scan "$share" "$sub" $((depth + 1))
    done
}

# ── Scan a single share ───────────────────────────────────────────────────────
scan_share() {
    local raw_share="$1"

    local share start_path
    if [[ "$raw_share" == */* ]]; then
        share="${raw_share%%/*}"
        start_path="${raw_share#*/}"
    else
        share="$raw_share"
        start_path=""
    fi

    local rr wr dr write_result
    rr=$(test_read "$share" "$start_path")
    write_result=$(test_write "$share" "$start_path")
    wr=$(echo "$write_result" | awk '{print $1}')
    dr=$(echo "$write_result" | awk '{print $2}')
    print_line "$share" "$start_path" "$rr" "$wr" "$dr"

    if [[ "$rr" == "NOPRIVILEGE" || "$rr" == "NOTFOUND" || ( "$rr" == "DENIED" && "$wr" == "DENIED" ) ]]; then
        return
    fi

    [[ "$rr" == "ALLOWED" ]] && deep_scan "$share" "$start_path" 1
}

# ── Write structured output to file ──────────────────────────────────────────
write_output_file() {
    [[ -z "$OUT_FILE" ]] && return

    case "$OUT_FORMAT" in
        json)
            {
                echo "["
                local last=$((${#JSON_ROWS[@]} - 1))
                for i in "${!JSON_ROWS[@]}"; do
                    if [[ $i -lt $last ]]; then
                        echo "  ${JSON_ROWS[$i]},"
                    else
                        echo "  ${JSON_ROWS[$i]}"
                    fi
                done
                echo "]"
            } > "$OUT_FILE"
            echo -e "\n${G}[+]${N} JSON saved → ${C}${OUT_FILE}${N}"
            ;;
        csv)
            {
                echo "type,target,port,share,path,read,write,delete,access"
                for row in "${CSV_ROWS[@]}"; do
                    echo "$row"
                done
            } > "$OUT_FILE"
            echo -e "\n${G}[+]${N} CSV saved → ${C}${OUT_FILE}${N}"
            ;;
        normal)
            echo -e "\n${G}[+]${N} Output saved → ${C}${OUT_FILE}${N}"
            ;;
    esac
}

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    local auth_method
    if [[ "$KERBEROS" == true ]]; then
        auth_method="Kerberos"
    elif [[ "$NULL" == true ]]; then
        auth_method="Null session"
    elif [[ -n "$HASH" ]]; then
        local nt="${HASH##*:}"
        auth_method="${DOMAIN:+${DOMAIN}/}${USER}:<${nt}>"
    elif [[ -n "$USER" && -z "$PASS" ]]; then
        auth_method="${DOMAIN:+${DOMAIN}/}${USER}:<Password Null>"
    elif [[ -n "$USER" && -n "$PASS" ]]; then
        auth_method="${DOMAIN:+${DOMAIN}/}${USER}:${PASS}"
    else
        auth_method="Null session"
    fi

    local shares_label
    if [[ "$AUTO_ENUM" == true ]]; then
        shares_label="Auto Discovery"
    else
        shares_label="$(IFS=', '; echo "${SHARES[*]}")"
    fi

    local sleep_label
    if [[ "$SLEEP" == "0" || -z "$SLEEP" ]]; then
        sleep_label="0s"
    else
        sleep_label="${SLEEP}s +jitter"
    fi

    local format_label
    if [[ -n "$OUT_FILE" ]]; then
        format_label="${OUT_FILE}"
    else
        format_label="Terminal"
    fi

    local ext_label=""
    if [[ "$EXT_ALL" == true ]]; then
        ext_label="All"
    elif [[ ${#EXT_FILTER[@]} -gt 0 ]]; then
        ext_label="${EXT_FILTER[*]}"
    fi

    local target_label
    target_label="$(IFS=', '; echo "${TARGETS[*]}")"

    echo -e "${D}deepshare  by JazzTheRabbit${N}"
    echo -e ""
    printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "Target"  "$target_label"
    printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "Shares"  "$shares_label"
    printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "Auth"    "$auth_method"
    printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "NetBIOS"  "$SPOOF_NAME"
    printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "Timeout" "${TIMEOUT} Seconds"
    printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "Sleep"   "$sleep_label"
    [[ "$DRY_RUN"   == true ]] && printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "Mode" "No-Write"
    [[ "$LIST_ONLY" == true ]] && printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "Mode" "List Only"
    [[ -n "$ext_label" ]] && \
        printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "Ext"  "$ext_label"
    printf "  ${B}${W}%-9s${N}  ${D}%s${N}\n" "Format"  "$format_label"
    echo -e ""
}

# ── Validate session before scanning ─────────────────────────────────────────
validate_session() {
    local out
    out=$(smbclient -L "//${TARGET}" "${SMB_AUTH[@]}" 2>&1)

    if [[ "$NULL" == true ]] && echo "$out" | grep -qiE "NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE"; then
        printf "${B}SMB${N}  ${C}%-15s${N}  ${D}445${N}  ${R}[NULL SESSION DISABLED]${N}\n" "$TARGET"
        return 1
    fi

    if echo "$out" | grep -qiE "NT_STATUS_LOGON_FAILURE|NT_STATUS_ACCOUNT_DISABLED|NT_STATUS_ACCOUNT_LOCKED_OUT|NT_STATUS_PASSWORD_EXPIRED|NT_STATUS_WRONG_PASSWORD"; then
        printf "${B}SMB${N}  ${C}%-15s${N}  ${D}445${N}  ${R}[AUTH FAILED]${N}\n" "$TARGET"
        return 1
    fi

    if echo "$out" | grep -qiE "NT_STATUS_CONNECTION_REFUSED|NT_STATUS_HOST_UNREACHABLE|NT_STATUS_IO_TIMEOUT|failed to connect"; then
        printf "${B}SMB${N}  ${C}%-15s${N}  ${D}445${N}  ${M}[UNREACHABLE]${N}\n" "$TARGET"
        return 1
    fi

    return 0
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    local missing=()
    local deps=("smbclient" "awk" "tr" "sed")
    for dep in "${deps[@]}"; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${R}[!] Missing dependencies: ${missing[*]}${N}"
        echo -e ""
        echo -e "    Install on Debian/Ubuntu:  ${D}sudo apt install samba-common-bin${N}"
        echo -e "    Install on Arch:           ${D}sudo pacman -S smbclient${N}"
        echo -e "    Install on Fedora/RHEL:    ${D}sudo dnf install samba-client${N}"
        echo -e ""
        exit 1
    fi

    smb_auth
    print_banner

    for TARGET in "${TARGETS[@]}"; do
        if ! validate_session; then
            continue
        fi

        if [[ "$AUTO_ENUM" == true ]]; then
            SHARES=()
            if ! enum_shares; then
                continue
            fi
        fi

        if [[ "$LIST_ONLY" == true ]]; then
            for share in "${SHARES[@]}"; do
                local rr wr dr write_result
                rr=$(test_read "$share" "")
                if [[ "$DRY_RUN" == true ]]; then
                    wr="SKIPPED"
                    dr="SKIPPED"
                else
                    write_result=$(test_write "$share" "")
                    wr=$(echo "$write_result" | awk '{print $1}')
                    dr=$(echo "$write_result" | awk '{print $2}')
                fi
                print_line "$share" "" "$rr" "$wr" "$dr"
            done
        else
            for share in "${SHARES[@]}"; do
                scan_share "$share"
            done
        fi
    done



    write_output_file
    echo ""
}

main "$@"
