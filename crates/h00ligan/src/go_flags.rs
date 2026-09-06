//! Go build configuration admitted by the product's existing toolchain owner.
//!
//! Preserve caller selection without permitting module writes or introducing
//! unwitnessed manifests, overlays, compiler wrappers, or package directories.

/// GOFLAGS uses Go's quoted-field syntax, not shell escaping. Inspect fields
/// using the same rules while retaining the original admitted bytes for Go.
/// See https://go.dev/src/cmd/internal/quoted/quoted.go and
/// https://go.dev/src/cmd/go/internal/base/goflags.go (checked 2026-09-06).
pub fn resolve(requested: Option<&str>) -> Result<String, String> {
    let requested = requested.unwrap_or_default();
    let mut remaining = requested;
    let mut explicit_module_mode = false;
    while !remaining.is_empty() {
        remaining = remaining.trim_start_matches([' ', '\t', '\n', '\r']);
        if remaining.is_empty() {
            break;
        }
        let field;
        if remaining.starts_with(['\'', '"']) {
            let quote = char::from(remaining.as_bytes()[0]);
            remaining = &remaining[1..];
            let end = remaining
                .find(quote)
                .ok_or("invalid GOFLAGS: unterminated quoted field")?;
            field = &remaining[..end];
            remaining = &remaining[end + 1..];
        } else {
            let end = remaining
                .find([' ', '\t', '\n', '\r'])
                .unwrap_or(remaining.len());
            field = &remaining[..end];
            remaining = &remaining[end..];
        }
        let option = field
            .strip_prefix("--")
            .or_else(|| field.strip_prefix('-'))
            .ok_or("invalid GOFLAGS: use -name=value fields, not positional arguments")?;
        let (name, value) = option
            .split_once('=')
            .map_or((option, None), |(name, value)| (name, Some(value)));
        let valid = match name {
            "tags" => value.is_some(),
            "mod" => {
                if value != Some("readonly") {
                    return Err("Go semantic indexing requires -mod=readonly; module updates and vendor mode are not supported".into());
                }
                explicit_module_mode = true;
                true
            }
            "p" => value
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|n| n > 0),
            "race" | "msan" | "asan" | "trimpath" | "v" | "x" | "a" => {
                matches!(value, None | Some("true" | "false"))
            }
            "buildvcs" => matches!(value, None | Some("auto" | "true" | "false")),
            _ => {
                return Err(format!(
                    "unsupported GOFLAGS option -{name}: semantic indexing supports -tags, -mod=readonly, -p, -race, -msan, -asan, -trimpath, -buildvcs, -a, -v and -x; alternate manifests, overlays and compiler/package redirection need tracked input support"
                ));
            }
        };
        if !valid {
            return Err(format!(
                "invalid GOFLAGS value for -{name}; use Go's -name=value syntax"
            ));
        }
    }
    if explicit_module_mode {
        Ok(requested.to_owned())
    } else if requested.trim_matches([' ', '\t', '\n', '\r']).is_empty() {
        Ok("-mod=readonly".into())
    } else {
        Ok(format!("-mod=readonly {requested}"))
    }
}

#[cfg(test)]
mod tests {
    use super::resolve;

    #[test]
    fn default_and_explicit_profiles_preserve_go_quoted_fields() {
        for empty in [None, Some(""), Some(" \r\n\t")] {
            assert_eq!(resolve(empty).unwrap(), "-mod=readonly");
        }
        for flags in [
            "-mod=readonly -tags=contract_red",
            "--mod=readonly '--tags=alpha beta' -p=4 -trimpath",
            "\"-mod=readonly\"\t\"-tags=alpha,beta\"",
            "-mod=readonly -tags= -race=false -buildvcs=auto",
            "-mod=readonly -tags=alpha -tags=beta",
            "-mod=readonly -tags=unicode_é",
        ] {
            assert_eq!(resolve(Some(flags)).unwrap(), flags);
        }
        assert_eq!(
            resolve(Some("'-tags=alpha beta'")).unwrap(),
            "-mod=readonly '-tags=alpha beta'"
        );
    }

    #[test]
    fn malformed_mutating_and_untracked_profiles_are_never_silently_replaced() {
        for flags in [
            "-mod=mod",
            "--mod=vendor",
            "'-mod=mod'",
            "-mod=readonly -mod=mod",
            "-mod=mod -mod=readonly",
            "-mod",
            "-mod=",
            "-modfile=other.mod",
            "--overlay=overlay.json",
            "'-pkgdir=other path'",
            "-toolexec=wrapper",
            "-compiler=gccgo",
            "-gcflags=-Iother",
            "-C=elsewhere",
            "-tags alpha",
            "-tags",
            "'-tags=alpha",
            "-tags='alpha beta'",
            "''",
            "---tags=alpha",
            "-p=0",
            "-p=wat",
            "-race=wat",
            "-buildvcs=wat",
        ] {
            assert!(
                resolve(Some(flags)).is_err(),
                "must refuse unsupported selection: {flags}"
            );
        }
        assert!(
            resolve(Some("-tags=contract_red")).is_ok(),
            "positive supported selector"
        );
    }
}
