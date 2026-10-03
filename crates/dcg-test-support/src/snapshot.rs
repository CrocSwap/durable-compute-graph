// SPDX-License-Identifier: GPL-3.0-only
//! Saved real-flow states (owner decision 2026-10-02). A snapshot holds only
//! accounts a real builder run produced; it is keyed by the fixture digest,
//! the program identity and the builder version, and a regeneration check
//! (`matches`) compares a fresh real run byte for byte.
