Persist the files the guest wrote, so a guest-side experiment can report

The guest filesystem is memory-only: win_file holds a std::vector and NtWriteFile fills it, so
when the emulator process ends the bytes go with it. That is harmless while the guest is a
driver whose result is visible in its return status, and a hard blocker the moment the guest
has to produce something -- which is exactly what the objective now needs: run b.dll inside a
guest user-mode process and get its crypto output back out to the host.

Measured: guestprobe.exe calls NtCreateFile('c:/guestprobe.out') and NtWriteFile(15 bytes),
the emulator reports success, and before this change the file existed nowhere on the host.
After it, guest-out/c/guestprobe.out contains GUEST_PROBE_RAN.

  filesystem.hpp  win_file tracks whether the guest put bytes into it; the dump keys on
                  dirtiness rather than creation, because boot_seed creates physicaldriveN
                  placeholders that would otherwise be dumped as noise, and a guest editing
                  a host-loaded file should be visible too
  filesystem.cpp  dump_dirty_files mirrors each dirty guest path under the host directory,
                  drive letter down; a path without the drive-letter shape is skipped rather
                  than joined, so the dump cannot be steered outside its directory
  main.cpp        called after run_all, before the per-image status lines

The loader is not involved in any of this; it already runs to completion (0118).
