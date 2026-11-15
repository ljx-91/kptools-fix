#!/usr/bin/env python3
"""Apply and verify fail-closed native executable staging for Y73s FolkPatch."""

from __future__ import annotations

import argparse
from pathlib import Path

OLD = '''        for (lib in libs) {
            val name = lib.name.substring(3, lib.name.length - 3)
            try {
                Os.symlink(lib.path, "$patchDir/$name")
            } catch (e: Exception) {
                lib.inputStream().copyAndClose(File(patchDir, name).outputStream())
            }
        }
'''

NEW = '''        val stagedExecutables = mutableSetOf<String>()
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

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()

    source = args.source
    text = source.read_text(encoding="utf-8")
    if NEW in text:
        print("Y73s fail-closed executable staging already applied")
        return
    count = text.count(OLD)
    if count != 1:
        raise SystemExit(
            f"Expected exactly one original executable staging block, found {count}; refusing to patch"
        )
    patched = text.replace(OLD, NEW, 1)
    if "Cannot stage native executable $name via symlink" not in patched:
        raise SystemExit("Patched source verification failed")
    source.write_text(patched, encoding="utf-8")
    print("Applied Y73s fail-closed executable staging")

if __name__ == "__main__":
    main()
