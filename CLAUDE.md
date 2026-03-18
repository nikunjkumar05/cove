The role of this file is to describe common mistakes and confusion points that agents might encounter as they work in this project. If you ever encounter something in the project that surprises you, please alert the developer working with you and indicate that this is the case in the CLAUDE.md file to help prevent future agents from having the same issue.

- no mod.rs files use the other format module_name.rs
- Use `cove_util::ResultExt::map_err_str` instead of `.map_err(|e| Error::Variant(e.to_string()))` — it's cleaner and equivalent
- Use `cove_util::ResultExt::map_err_prefix` instead of `.map_err(|e| Error::Variant(format!("context: {e}")))` when the prefix is a static string — produces `"context: error_message"`
