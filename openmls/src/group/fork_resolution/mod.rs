//! This module contains facilities for dealing with state forks, i.e. situations in which
//! different parts of a group merged different commits. Here, we provide helpers for two
//! approaches, that come with different requirements and performance profiles.
//!
//! The [`readd`] module contains helpers for removing and re-adding members that merged a wrong
//! commit. It is the responsibility of the application to determine which commit is the right one,
//! as well as which members need to be re-added. This is a relatively cheap mechanism, but it
//! requires knowing about the partitions.
//!
//! The [`reboot`] module contains helpers to set up a new group and add all members of the current
//! group. The application needs to determine who should set that new group up and how to migrate
//! the group context extensions from the old group. This is the more expensive mechanism.

mod readd;
mod reboot;
