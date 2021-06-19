#[cfg(test)]
mod tests;

use std::path::Path;

use crate::errors::Result;
use crate::utils::*;

/// Return the top-level SELinux configuration directory.
///
/// See: `selinux_path()`.
pub fn selinux() -> Result<&'static Path> {
    get_static_path(selinux_sys::selinux_path, "selinux_path()")
}

/// Return the context file mapping roles to default types.
///
/// See: `selinux_default_type_path()`.
pub fn default_type_path() -> Result<&'static Path> {
    let proc_name = "selinux_default_type_path()";
    get_static_path(selinux_sys::selinux_default_type_path, proc_name)
}

/// Return the fail-safe context for emergency logins.
///
/// See: `selinux_failsafe_context_path()`.
pub fn fail_safe_context() -> Result<&'static Path> {
    let proc_name = "selinux_failsafe_context_path()";
    get_static_path(selinux_sys::selinux_failsafe_context_path, proc_name)
}

/// Return the file system context for removable media.
///
/// See: `selinux_removable_context_path()`.
pub fn removable_context() -> Result<&'static Path> {
    let proc_name = "selinux_removable_context_path()";
    get_static_path(selinux_sys::selinux_removable_context_path, proc_name)
}

/// Return the system-wide default contexts for user sessions.
///
/// See: `selinux_default_context_path()`.
pub fn default_context() -> Result<&'static Path> {
    let proc_name = "selinux_default_context_path()";
    get_static_path(selinux_sys::selinux_default_context_path, proc_name)
}

/// Return the directory containing per-user default contexts.
///
/// See: `selinux_user_contexts_path()`.
pub fn user_contexts() -> Result<&'static Path> {
    let proc_name = "selinux_user_contexts_path()";
    get_static_path(selinux_sys::selinux_user_contexts_path, proc_name)
}

/// Return the default system file contexts configuration.
///
/// See: `selinux_file_context_path()`.
pub fn file_context() -> Result<&'static Path> {
    let proc_name = "selinux_file_context_path()";
    get_static_path(selinux_sys::selinux_file_context_path, proc_name)
}

/// Return the home directory file contexts configuration.
///
/// See: `selinux_file_context_homedir_path()`.
pub fn file_context_homedir() -> Result<&'static Path> {
    let proc_name = "selinux_file_context_homedir_path()";
    get_static_path(selinux_sys::selinux_file_context_homedir_path, proc_name)
}

/// Return the local customization file contexts configuration.
///
/// See: `selinux_file_context_local_path()`.
pub fn file_context_local() -> Result<&'static Path> {
    let proc_name = "selinux_file_context_local_path()";
    get_static_path(selinux_sys::selinux_file_context_local_path, proc_name)
}

/// See: `selinux_file_context_subs_path()`.
pub fn file_context_subs() -> Result<&'static Path> {
    let proc_name = "selinux_file_context_subs_path()";
    get_static_path(selinux_sys::selinux_file_context_subs_path, proc_name)
}

/// See: `selinux_file_context_subs_dist_path()`.
pub fn file_context_subs_dist() -> Result<&'static Path> {
    let proc_name = "selinux_file_context_subs_dist_path()";
    get_static_path(selinux_sys::selinux_file_context_subs_dist_path, proc_name)
}

/// See: `selinux_homedir_context_path()`.
pub fn home_dir_context() -> Result<&'static Path> {
    let proc_name = "selinux_homedir_context_path()";
    get_static_path(selinux_sys::selinux_homedir_context_path, proc_name)
}

/// Return the file contexts for media device nodes.
///
/// See: `selinux_media_context_path()`.
pub fn media_context() -> Result<&'static Path> {
    let proc_name = "selinux_media_context_path()";
    get_static_path(selinux_sys::selinux_media_context_path, proc_name)
}

/// See: `selinux_virtual_domain_context_path()`.
pub fn virtual_domain_context() -> Result<&'static Path> {
    let proc_name = "selinux_virtual_domain_context_path()";
    get_static_path(selinux_sys::selinux_virtual_domain_context_path, proc_name)
}

/// See: `selinux_virtual_image_context_path()`.
pub fn virtual_image_context() -> Result<&'static Path> {
    let proc_name = "selinux_virtual_image_context_path()";
    get_static_path(selinux_sys::selinux_virtual_image_context_path, proc_name)
}

/// See: `selinux_lxc_contexts_path()`.
pub fn lxc_contexts() -> Result<&'static Path> {
    let proc_name = "selinux_lxc_contexts_path()";
    get_static_path(selinux_sys::selinux_lxc_contexts_path, proc_name)
}

/// Return the file containing configuration for XSELinux extension.
///
/// See: `selinux_x_context_path()`.
pub fn x_context() -> Result<&'static Path> {
    let proc_name = "selinux_x_context_path()";
    get_static_path(selinux_sys::selinux_x_context_path, proc_name)
}

/// Return the file containing configuration for SE-PostgreSQL.
///
/// See: `selinux_sepgsql_context_path()`.
pub fn sepgsql_context() -> Result<&'static Path> {
    let proc_name = "selinux_sepgsql_context_path()";
    get_static_path(selinux_sys::selinux_sepgsql_context_path, proc_name)
}

/// See: `selinux_openrc_contexts_path()`.
pub fn openrc_contexts() -> Result<&'static Path> {
    let proc_name = "selinux_openrc_contexts_path()";
    get_static_path(selinux_sys::selinux_openrc_contexts_path, proc_name)
}

/// See: `selinux_openssh_contexts_path()`.
pub fn openssh_contexts() -> Result<&'static Path> {
    let proc_name = "selinux_openssh_contexts_path()";
    get_static_path(selinux_sys::selinux_openssh_contexts_path, proc_name)
}

/// See: `selinux_snapperd_contexts_path()`.
pub fn snapperd_contexts() -> Result<&'static Path> {
    let proc_name = "selinux_snapperd_contexts_path()";
    get_static_path(selinux_sys::selinux_snapperd_contexts_path, proc_name)
}

/// See: `selinux_systemd_contexts_path()`.
pub fn systemd_contexts() -> Result<&'static Path> {
    let proc_name = "selinux_systemd_contexts_path()";
    get_static_path(selinux_sys::selinux_systemd_contexts_path, proc_name)
}

/// Return the directory containing all of the context configuration files.
///
/// See: `selinux_contexts_path()`.
pub fn contexts() -> Result<&'static Path> {
    let proc_name = "selinux_contexts_path()";
    get_static_path(selinux_sys::selinux_contexts_path, proc_name)
}

/// Return the defines tty types for newrole securettys.
///
/// See: `selinux_securetty_types_path()`.
pub fn securetty_types() -> Result<&'static Path> {
    let proc_name = "selinux_securetty_types_path()";
    get_static_path(selinux_sys::selinux_securetty_types_path, proc_name)
}

/// See: `selinux_booleans_subs_path()`.
pub fn booleans_subs() -> Result<&'static Path> {
    let proc_name = "selinux_booleans_subs_path()";
    get_static_path(selinux_sys::selinux_booleans_subs_path, proc_name)
}

/// See: `selinux_customizable_types_path()`.
pub fn customizable_types() -> Result<&'static Path> {
    let proc_name = "selinux_customizable_types_path()";
    get_static_path(selinux_sys::selinux_customizable_types_path, proc_name)
}

/// Return the file containing mapping between Linux users and SELinux users.
///
/// See: `selinux_usersconf_path()`.
pub fn users_conf() -> Result<&'static Path> {
    let proc_name = "selinux_usersconf_path()";
    get_static_path(selinux_sys::selinux_usersconf_path, proc_name)
}

/// See: `selinux_translations_path()`.
pub fn translations() -> Result<&'static Path> {
    let proc_name = "selinux_translations_path()";
    get_static_path(selinux_sys::selinux_translations_path, proc_name)
}

/// See: `selinux_colors_path()`.
pub fn colors() -> Result<&'static Path> {
    get_static_path(selinux_sys::selinux_colors_path, "selinux_colors_path()")
}

/// Return the default netfilter context.
///
/// See: `selinux_netfilter_context_path()`.
pub fn netfilter_context() -> Result<&'static Path> {
    let proc_name = "selinux_netfilter_context_path()";
    get_static_path(selinux_sys::selinux_netfilter_context_path, proc_name)
}
