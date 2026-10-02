//! Detection rules: every rule inspects one line (plus a little file-level context) and reports places where
//! code assumes that a Git object name is 40 hex characters (SHA-1) instead of "whatever length Git gives you".

use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
    pub fn parse(s: &str) -> Option<Severity> {
        match s {
            "info" => Some(Severity::Info),
            "warning" => Some(Severity::Warning),
            "error" => Some(Severity::Error),
            _ => None,
        }
    }
}

pub struct RuleInfo {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub why: &'static str,
    pub fix: &'static str,
}

pub const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "hex40-pattern",
        severity: Severity::Error,
        title: "Pattern that only matches exactly 40 hex characters",
        why: "A regex such as [0-9a-f]{40} rejects every SHA-256 object name (64 hex characters).",
        fix: "Accept both lengths: [0-9a-f]{40}([0-9a-f]{24})?  or  [0-9a-f]{40,64}; better, validate with `git rev-parse --verify`.",
    },
    RuleInfo {
        id: "hex-range-max-40",
        severity: Severity::Error,
        title: "Hex pattern whose upper bound is 40 characters",
        why: "{7,40}-style ranges are used to accept abbreviated and full hashes; the upper bound cuts off 64-character names.",
        fix: "Raise the upper bound to 64: [0-9a-f]{7,64}.",
    },
    RuleInfo {
        id: "length-40",
        severity: Severity::Error,
        title: "Length of a hash compared with 40",
        why: "`len(sha) == 40` is false for every SHA-256 name, so valid revisions are rejected or take a fallback path.",
        fix: "Do not validate by length. Ask git: `git rev-parse --verify <name>^{commit}`; or accept 40 or 64.",
    },
    RuleInfo {
        id: "truncate-40",
        severity: Severity::Error,
        title: "Hash cut at 40 characters",
        why: "Cutting at position 40 silently turns a 64-character name into a different, invalid one. It does not fail loudly, it stores the wrong value.",
        fix: "Keep the full name. For display use `git rev-parse --short` or `git log --format=%h`.",
    },
    RuleInfo {
        id: "column-40",
        severity: Severity::Error,
        title: "Column or field sized for 40 characters",
        why: "A CHAR(40)/VARCHAR(40)/String(40)/max_length=40 field holding a revision rejects or truncates 64-character names.",
        fix: "Widen to at least 64 (or use TEXT) and store the full object name.",
    },
    RuleInfo {
        id: "bytes-20",
        severity: Severity::Warning,
        title: "Raw object id stored in 20 bytes",
        why: "SHA-1 object ids are 20 raw bytes, SHA-256 ids are 32.",
        fix: "Size buffers from the repository's hash algorithm (`git rev-parse --show-object-format`) or use a variable-length type.",
    },
    RuleInfo {
        id: "null-oid",
        severity: Severity::Error,
        title: "All-zero 40 character object id",
        why: "Hooks and CI scripts compare against 40 zeros to detect a new or deleted branch; in a SHA-256 repository the null id has 64 zeros.",
        fix: "Match any run of zeros: `^0+$` (shell: `case $oldrev in *[!0]*) ;; *) is_null=1 ;; esac`), or use `git hash-object --stdin </dev/null`-style helpers.",
    },
    RuleInfo {
        id: "empty-tree-sha1",
        severity: Severity::Warning,
        title: "Hard-coded SHA-1 id of the empty tree or empty blob",
        why: "The well-known empty-tree id 4b825dc... exists only in SHA-1 repositories. In SHA-256 repositories it is 6ef19b41....",
        fix: "Compute it: `git hash-object -t tree /dev/null` (or `git mktree </dev/null`).",
    },
    RuleInfo {
        id: "abbrev-40",
        severity: Severity::Warning,
        title: "--abbrev=40 used to get a full hash",
        why: "`--abbrev=40` means \"full length\" only for SHA-1; in SHA-256 repositories it still abbreviates.",
        fix: "Use `--no-abbrev` (or `--abbrev=no`) to ask for the full name.",
    },
    RuleInfo {
        id: "api-constant",
        severity: Severity::Warning,
        title: "Library constant that fixes the object id size",
        why: "Constants such as GIT_OID_HEXSZ or OBJECT_ID_STRING_LENGTH describe SHA-1 only.",
        fix: "Use the algorithm-aware API of the library (for example the object-format specific constants in libgit2, or ObjectId/Constants helpers in JGit).",
    },
    RuleInfo {
        id: "sha1-object-hash",
        severity: Severity::Warning,
        title: "Re-implements git's object hashing with SHA-1",
        why: "Computing sha1(\"blob <size>\\0\" + data) by hand only reproduces ids of SHA-1 repositories.",
        fix: "Call `git hash-object` (it honours the repository's object format) instead of hashing yourself.",
    },
];

pub fn rule(id: &str) -> &'static RuleInfo {
    RULES.iter().find(|r| r.id == id).expect("known rule id")
}

#[derive(Clone, Debug, Serialize)]
pub struct Hit {
    pub rule: &'static str,
    pub severity: Severity,
    pub column: usize,
    pub message: String,
}

struct Patterns {
    hex40: Regex,
    hex_range: Regex,
    len40: Regex,
    len40_rev: Regex,
    truncate: Regex,
    column: Regex,
    bytes20: Regex,
    null_oid: Regex,
    empty_tree: Regex,
    abbrev: Regex,
    api_const: Regex,
    blob_header: Regex,
    dual: Regex,
    sha1_word: Regex,
    hashy: Regex,
}

const HEXCLASS: &str = r"(?:\[[^\]\n]*(?:0-9a-f|a-f0-9|0-9A-F|A-F0-9)[^\]\n]*\]|\[\[:xdigit:\]\]|\\h|\\p\{XDigit\})";

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        hex40: Regex::new(&format!(r"(?i){HEXCLASS}\{{40\}}")).unwrap(),
        hex_range: Regex::new(&format!(r"(?i){HEXCLASS}\{{\s*\d*\s*,\s*40\s*\}}")).unwrap(),
        // len(x) == 40, x.length === 40, strlen($x) != 40, ${#x} -eq 40, x.len() == 40
        len40: Regex::new(r"(?i)(?:\blen\s*\(|\blength\b|\bstrlen\s*\(|\bsize\b|\.len\s*\(\s*\)|\.count\b|\$\{#\w+\}|\bmb_strlen\s*\()[^\n]{0,40}?(?:===?|!==?|-eq|-ne|<=|>=|<>)\s*40\b").unwrap(),
        len40_rev: Regex::new(r"(?i)\b40\s*(?:===?|!==?|-eq|-ne)\s*(?:len\s*\(|strlen\s*\(|\w+\.length\b|\w+\.len\s*\()").unwrap(),
        truncate: Regex::new(
            r"(?ix)
            \bcut\s+-[cb]\s*1-40\b
            | \bhead\s+-c\s*40\b
            | \[\s*(?:0)?\s*:\s*40\s*\]
            | \[\s*(?:0)?\s*\.\.\s*40\s*\]
            | \.(?:substring|slice|substr)\s*\(\s*0\s*,\s*40\s*\)
            | \bsubstr\s*\([^\n)]*,\s*0\s*,\s*40\s*\)
            | \$\{\w+:0:40\}
            | %\.40s
            | \.take\s*\(\s*40\s*\)
            | \bLEFT\s*\([^\n)]*,\s*40\s*\)
            ",
        )
        .unwrap(),
        column: Regex::new(
            r"(?ix)
            \b(?:var)?char(?:acter)?(?:\s+varying)?\s*\(\s*40\s*\)
            | \bString\s*\(\s*40\s*\)
            | \bnvarchar\s*\(\s*40\s*\)
            | \bmax_?length\s*[:=]\s*40\b
            | \blength\s*=\s*40\b
            | \.string\s*\([^\n)]*,\s*40\s*\)
            | \bvarbinary\s*\(\s*20\s*\)
            | \bbinary\s*\(\s*20\s*\)
            | \bmaxLength\s*:\s*40\b
            | \bminLength\s*:\s*40\b
            | \bsize\s*=\s*40\b
            ",
        )
        .unwrap(),
        bytes20: Regex::new(r"(?i)\[\s*20\s*\]\s*(?:u?byte|uint8)\b|\[\s*u8\s*;\s*20\s*\]|\bbyte\s*\[\s*20\s*\]|\buint8_t\s+\w+\s*\[\s*20\s*\]|\bunsigned\s+char\s+\w+\s*\[\s*20\s*\]|\bBuffer\.alloc\s*\(\s*20\s*\)|\bnew\s+byte\s*\[\s*20\s*\]").unwrap(),
        null_oid: Regex::new(r"(?:^|[^0-9A-Fa-f])0{40}(?:$|[^0-9A-Fa-f])").unwrap(),
        empty_tree: Regex::new(r"(?i)(?:^|[^0-9a-f])(?:4b825dc642cb6eb9a060e54bf8d69288fbee4904|e69de29bb2d1d6434b8b29ae775ad8c2e48c5391)(?:$|[^0-9a-f])").unwrap(),
        abbrev: Regex::new(r"(?i)--abbrev(?:=|\s+)40\b|\bcore\.abbrev\s*[= ]\s*40\b|\babbrev\s*=\s*40\b").unwrap(),
        api_const: Regex::new(r"\b(?:GIT_OID_HEXSZ|GIT_OID_RAWSZ|GIT_SHA1_HEXSZ|GIT_SHA1_RAWSZ|GIT_MAX_HEXSZ_SHA1|OBJECT_ID_STRING_LENGTH|OBJECT_ID_LENGTH|GIT_OID_SHA1_HEXSIZE|GIT_OID_SHA1_SIZE)\b").unwrap(),
        blob_header: Regex::new(r#"["'`]blob\s+["'`]|["'`]blob\s*(?:%|\{|\$)"#).unwrap(),
        dual: Regex::new(r"\{\s*\d*\s*,?\s*64\s*\}|\b64\b").unwrap(),
        sha1_word: Regex::new(r"(?i)sha-?1").unwrap(),
        hashy: Regex::new(r"(?i)sha|hash|\boid|_oid|oid_|commit|revision|\brev\b|_rev\b|rev_|digest|object.?id|treeish|changeset|\bgit").unwrap(),
    })
}

/// File-level facts that some rules need.
pub struct FileContext {
    pub mentions_sha1: bool,
}

impl FileContext {
    pub fn new(text: &str) -> Self {
        FileContext { mentions_sha1: patterns().sha1_word.is_match(text) }
    }
}

fn is_comparison_error(line: &str) -> Severity {
    if line.contains("==") || line.contains("!=") || line.contains("-eq") || line.contains("-ne") {
        Severity::Error
    } else {
        Severity::Warning
    }
}

/// Inspect a single line.
pub fn check_line(line: &str, ctx: &FileContext) -> Vec<Hit> {
    let p = patterns();
    let mut out = Vec::new();
    let mut push = |rule: &'static str, severity: Severity, col: usize, message: &str| {
        out.push(Hit { rule, severity, column: col + 1, message: message.to_string() });
    };
    let hashy = p.hashy.is_match(line);
    // Lines that already mention 64 usually support both hash sizes on purpose.
    let dual = p.dual.is_match(line);

    if let Some(m) = p.hex40.find(line).filter(|_| !dual) {
        push("hex40-pattern", Severity::Error, m.start(), "pattern matches exactly 40 hex characters; SHA-256 names have 64");
    }
    if let Some(m) = p.hex_range.find(line).filter(|_| !dual) {
        push("hex-range-max-40", Severity::Error, m.start(), "hex range ends at 40; SHA-256 names have 64 characters");
    }
    if hashy {
        if let Some(m) = p.len40.find(line).or_else(|| p.len40_rev.find(line)).filter(|_| !dual) {
            push("length-40", is_comparison_error(line), m.start(), "length compared with 40; SHA-256 names have 64 characters");
        }
        if let Some(m) = p.truncate.find(line) {
            push("truncate-40", Severity::Error, m.start(), "value cut at 40 characters; a SHA-256 name would be truncated silently");
        }
        if let Some(m) = p.column.find(line) {
            push(
                "column-40",
                Severity::Error,
                m.start(),
                "field sized for 40 characters (or 20 bytes) holds a revision; SHA-256 names are 64 characters (32 bytes)",
            );
        }
        if let Some(m) = p.bytes20.find(line) {
            push("bytes-20", Severity::Warning, m.start(), "20-byte buffer for an object id; SHA-256 ids are 32 bytes");
        }
    }
    if let Some(m) = p.null_oid.find(line) {
        push("null-oid", Severity::Error, m.start(), "all-zero 40 character id; the SHA-256 null id has 64 zeros");
    }
    if let Some(m) = p.empty_tree.find(line) {
        push(
            "empty-tree-sha1",
            Severity::Warning,
            m.start(),
            "SHA-1 id of the empty tree/blob hard-coded; it differs in SHA-256 repositories",
        );
    }
    if let Some(m) = p.abbrev.find(line) {
        push("abbrev-40", Severity::Warning, m.start(), "--abbrev=40 asks for the full SHA-1 length only; use --no-abbrev");
    }
    if let Some(m) = p.api_const.find(line) {
        push("api-constant", Severity::Warning, m.start(), "constant describes the SHA-1 object id size");
    }
    if ctx.mentions_sha1 {
        if let Some(m) = p.blob_header.find(line) {
            push(
                "sha1-object-hash",
                Severity::Warning,
                m.start(),
                "builds a git object header next to SHA-1 code; call `git hash-object` instead",
            );
        }
    }
    // A literal that is explicitly labelled SHA-1 on the same line (NULL_SHA1, "sha1 empty tree")
    // is deliberate SHA-1 handling, not an accident: keep it visible but do not fail the build.
    if p.sha1_word.is_match(line) {
        for h in out.iter_mut() {
            if matches!(h.rule, "null-oid" | "empty-tree-sha1" | "hex40-pattern" | "hex-range-max-40") {
                h.severity = Severity::Info;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_for(line: &str) -> Vec<&'static str> {
        check_line(line, &FileContext::new(line)).into_iter().map(|h| h.rule).collect()
    }
    fn hits(line: &str, ctx_text: &str) -> Vec<&'static str> {
        check_line(line, &FileContext::new(ctx_text)).into_iter().map(|h| h.rule).collect()
    }

    #[test]
    fn hex40_patterns_in_many_dialects() {
        for l in [
            r#"re.compile(r"^[0-9a-f]{40}$")"#,
            "grep -E '^[0-9A-Fa-f]{40}$'",
            r"/\A[a-f0-9]{40}\z/",
            "pattern: '^[[:xdigit:]]{40}$'",
            "if (/^[0-9a-f]{40}$/.test(sha))",
        ] {
            assert!(rules_for(l).contains(&"hex40-pattern"), "{l}");
        }
    }

    #[test]
    fn hex_ranges_ending_at_40() {
        assert!(rules_for("re.match(r'^[0-9a-f]{7,40}$', ref)").contains(&"hex-range-max-40"));
        assert!(rules_for("[a-f0-9]{4,40}").contains(&"hex-range-max-40"));
        assert!(!rules_for("[0-9a-f]{4,64}").contains(&"hex-range-max-40"));
    }

    #[test]
    fn dual_support_is_not_reported() {
        assert!(rules_for("re.match(rb'(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40})', head)").is_empty());
        assert!(rules_for("if len(commit_hash) in (40, 64):").is_empty());
    }

    #[test]
    fn literal_hashes_and_action_pins_are_not_reported() {
        assert!(rules_for("uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v4").is_empty());
        assert!(rules_for("commit = \"fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09\"").is_empty());
        assert!(rules_for("rev: 6306c5c9d6c3b9ad0b3b1f2c8ad5a4d1e2f3a4b5").is_empty());
    }

    #[test]
    fn length_checks_need_a_hash_context() {
        assert!(rules_for("assert len(hexsha) == 40").contains(&"length-40"));
        assert!(rules_for("if (commitHash.length !== 40) throw").contains(&"length-40"));
        assert!(rules_for("if [ \"${#rev}\" -eq 40 ]; then").contains(&"length-40"));
        assert!(rules_for("if sha.len() == 40 {").contains(&"length-40"));
        // not about hashes
        assert!(rules_for("if len(title) == 40:").is_empty());
        assert!(rules_for("if (line.length == 40) wrap()").is_empty());
    }

    #[test]
    fn truncation_to_40() {
        for l in [
            "short=$(echo \"$sha\" | cut -c1-40)",
            "oldhexsha = info[:40]  # commit",
            "const id = commitHash.substring(0, 40);",
            "printf '%.40s' \"$hash\"",
            "head -c 40 <<< \"$rev\"",
        ] {
            assert!(rules_for(l).contains(&"truncate-40"), "{l}");
        }
        assert!(rules_for("name = title[:40]").is_empty());
    }

    #[test]
    fn database_columns() {
        assert!(rules_for("commit_sha VARCHAR(40) NOT NULL,").contains(&"column-40"));
        assert!(rules_for("CommitID string `xorm:\"VARCHAR(40)\"`").contains(&"column-40"));
        assert!(rules_for("object_id BINARY(20) -- git oid").contains(&"column-40"));
        assert!(rules_for("first_name VARCHAR(40)").is_empty());
    }

    #[test]
    fn byte_buffers() {
        assert!(rules_for("unsigned char hash_sha1[20];").contains(&"bytes-20"));
        assert!(rules_for("let oid: [u8; 20] = [0; 20]; // object id").contains(&"bytes-20"));
        assert!(rules_for("uint8_t buf[20];").is_empty());
    }

    #[test]
    fn null_oid_and_empty_tree() {
        assert!(rules_for("if [ \"$old\" = \"0000000000000000000000000000000000000000\" ]; then").contains(&"null-oid"));
        assert!(!rules_for("id = \"00000000000000000000000000000000000000000000000000000000000000000000\"").contains(&"null-oid"));
        assert!(rules_for("git diff 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD").contains(&"empty-tree-sha1"));
        assert!(rules_for("EMPTY_BLOB=e69de29bb2d1d6434b8b29ae775ad8c2e48c5391").contains(&"empty-tree-sha1"));
    }

    #[test]
    fn explicit_sha1_labels_are_info_only() {
        let h = check_line("const NULL_SHA1: &str = \"0000000000000000000000000000000000000000\";", &FileContext::new(""));
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].severity, Severity::Info);
    }

    #[test]
    fn abbrev_and_api_constants() {
        assert!(rules_for("git log --abbrev=40 -1").contains(&"abbrev-40"));
        assert!(!rules_for("git log --abbrev=7").contains(&"abbrev-40"));
        assert!(rules_for("char buf[GIT_OID_HEXSZ + 1];").contains(&"api-constant"));
        assert!(rules_for("assert(GIT_OID_SHA1_HEXSIZE == n)").contains(&"api-constant"));
    }

    #[test]
    fn blob_header_hashing_needs_sha1_in_file() {
        let sha1_file = "import hashlib\nhashlib.sha1(b\"blob \" + size)";
        assert!(hits("h = hashlib.sha1(b\"blob \" + str(n).encode())", sha1_file).contains(&"sha1-object-hash"));
        assert!(hits("header = f\"blob {len(data)}\\0\"", sha1_file).contains(&"sha1-object-hash"));
        // typing / ls-tree output / unrelated files
        assert!(hits("IndexObjUnion = Union[\"Tree\", \"Blob\", \"Submodule\"]", sha1_file).is_empty());
        assert!(hits("istream = IStream(\"blob\", len(data), io)", sha1_file).is_empty());
        assert!(hits("header = f\"blob {n}\"", "nothing about hashing here").is_empty());
    }

    #[test]
    fn every_rule_has_documentation() {
        for r in RULES {
            assert!(!r.title.is_empty() && !r.why.is_empty() && !r.fix.is_empty(), "{}", r.id);
        }
        assert_eq!(RULES.len(), 11);
    }
}
