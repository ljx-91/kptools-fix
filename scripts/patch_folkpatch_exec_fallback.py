#!/usr/bin/env python3
"""Apply fail-closed executable staging and initialization checks to Y73s FolkPatch."""

from __future__ import annotations

import argparse
from pathlib import Path

OLD_STAGE = '''        for (lib in libs) {
            val name = lib.name.substring(3, lib.name.length - 3)
            try {
                Os.symlink(lib.path, "$patchDir/$name")
            } catch (e: Exception) {
                lib.inputStream().copyAndClose(File(patchDir, name).outputStream())
            }
        }
'''

NEW_STAGE = '''        val stagedExecutables = mutableSetOf<String>()
        for (lib in libs) {
            if (!lib.isFile || !lib.canRead() || !lib.canExecute()) {
                throw IOException("Native executable is missing, unreadable, or non-executable: ${lib.path}")
            }
            val name = lib.name.substring(3, lib.name.length - 3)
            val dest = File(patchDir.path, name)
            try {
                Os.symlink(lib.absolutePath, dest.absolutePath)
            } catch (e: Exception) {
                // Do not copy into filesDir: app-private data may be no-exec under
                // Android SELinux even after chmod. Fail closed instead.
                throw IOException("Cannot stage native executable $name via symlink", e)
            }

            // File checks follow symlinks and validate the target under the app UID.
            if (!dest.isFile || !dest.canRead() || !dest.canExecute()) {
                throw IOException("Staged executable is unusable: ${dest.absolutePath}")
            }
            stagedExecutables.add(name)
        }

        val requiredExecutables = setOf("kptools", "busybox")
        val missingExecutables = requiredExecutables - stagedExecutables
        if (missingExecutables.isNotEmpty()) {
            throw IOException("Required native executables missing: ${missingExecutables.joinToString()}")
        }
'''

OLD_READY = '''            prepared = true
            return true
'''
NEW_READY = '''            if (error.isNotBlank()) {
                throw IOException("Patch environment validation failed: ${error.trim()}")
            }
            prepared = true
            return true
'''

def replace_once(source: str, old: str, new: str, label: str) -> str:
    if new in source:
        return source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one {label} block, found {count}; refusing to patch")
    return source.replace(old, new, 1)

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()

    source = args.source
    text = source.read_text(encoding="utf-8")
    text = replace_once(text, OLD_STAGE, NEW_STAGE, "native executable staging")
    text = replace_once(text, OLD_READY, NEW_READY, "prepared-state transition")
    if NEW_STAGE not in text or NEW_READY not in text:
        raise SystemExit("Patched source verification failed")
    source.write_text(text, encoding="utf-8")
    print("Applied Y73s fail-closed executable staging and initialization checks")

if __name__ == "__main__":
    main()
